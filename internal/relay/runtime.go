package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

const mqttOriginValue = "mqtt"

type Runtime struct {
	cfg         RuntimeConfig
	nc          *nats.Conn
	mqttServer  *mqtt.Server
	mapper      topicMapper
	credentials *credentialsStore
	subs        []*nats.Subscription
	subsMu      sync.Mutex
	echoMu      sync.Mutex
	recentEcho  map[string]time.Time
	closeOnce   sync.Once
	closeErr    error
}

func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	credentials, err := loadCredentials(cfg.MQTT.UsernamePasswordFile)
	if err != nil {
		return nil, err
	}

	nc, err := connectNATS(cfg.NATS)
	if err != nil {
		return nil, err
	}

	mochiLevel := new(slog.LevelVar)
	mochiLevel.Set(slog.LevelError)
	mochiLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: mochiLevel}))

	server := mqtt.New(&mqtt.Options{
		InlineClient: true,
		Logger:       mochiLogger,
	})
	r := &Runtime{
		cfg:         cfg,
		nc:          nc,
		mqttServer:  server,
		mapper:      newTopicMapper(cfg.Bridge.NATSPrefix, cfg.Bridge.MQTTPrefix),
		credentials: credentials,
		recentEcho:  map[string]time.Time{},
	}

	hook := &relayHook{runtime: r}
	if err := r.mqttServer.AddHook(hook, nil); err != nil {
		_ = nc.Drain()
		return nil, fmt.Errorf("add relay hook: %w", err)
	}

	tcp := listeners.NewTCP(listeners.Config{ID: "mpcium-relay", Address: cfg.MQTT.ListenAddress})
	if err := r.mqttServer.AddListener(tcp); err != nil {
		_ = nc.Drain()
		return nil, fmt.Errorf("add mqtt listener: %w", err)
	}

	return r, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := r.subscribeNATS(); err != nil {
		return err
	}
	if err := r.subscribeMQTTInline(); err != nil {
		return err
	}
	if err := r.mqttServer.Serve(); err != nil {
		return fmt.Errorf("mqtt server stopped: %w", err)
	}

	logger.Info("relay runtime started", "mqtt_listen", r.cfg.MQTT.ListenAddress, "nats_url", r.cfg.NATS.URL)

	<-ctx.Done()
	return r.Close()
}

func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.subsMu.Lock()
		for _, sub := range r.subs {
			_ = sub.Unsubscribe()
		}
		r.subs = nil
		r.subsMu.Unlock()

		if r.mqttServer != nil {
			if err := r.mqttServer.Close(); err != nil {
				r.closeErr = err
			}
		}
		if r.nc != nil && !r.nc.IsClosed() {
			if err := r.nc.Drain(); err != nil {
				r.nc.Close()
			}
		}
	})
	return r.closeErr
}

func (r *Runtime) subscribeNATS() error {
	for _, filter := range []string{r.mapper.natsControlFilter(), r.mapper.natsP2PFilter()} {
		filter := filter
		logger.Info("relay subscribed NATS filter", "filter", filter)
		sub, err := r.nc.Subscribe(filter, func(msg *nats.Msg) {
			if strings.EqualFold(msg.Header.Get(r.cfg.Bridge.OriginHeader), mqttOriginValue) {
				return
			}
			topic, ok := r.mapper.natsToMQTT(msg.Subject)
			if !ok {
				return
			}
			logger.Debug("relay bridge NATS->MQTT", "subject", msg.Subject, "topic", topic, "bytes", len(msg.Data))
			r.markNATSEcho(topic, msg.Data)
			if err := r.mqttServer.Publish(topic, msg.Data, false, r.cfg.Bridge.MQTTQoS); err != nil {
				logger.Error("relay publish NATS->MQTT failed", err, "subject", msg.Subject, "topic", topic)
			}
		})
		if err != nil {
			return fmt.Errorf("subscribe nats filter %s: %w", filter, err)
		}
		r.subsMu.Lock()
		r.subs = append(r.subs, sub)
		r.subsMu.Unlock()
	}

	if err := r.nc.Flush(); err != nil {
		return fmt.Errorf("flush nats subscriptions: %w", err)
	}
	return nil
}

func (r *Runtime) subscribeMQTTInline() error {
	for idx, filter := range []string{r.mapper.mqttP2PFilter(), r.mapper.mqttSessionEventFilter(), r.mapper.mqttPresenceFilter()} {
		filter := filter
		subID := idx + 1
		logger.Info("relay subscribed MQTT filter", "filter", filter, "sub_id", subID)
		if err := r.mqttServer.Subscribe(filter, subID, func(cl *mqtt.Client, _ packets.Subscription, pk packets.Packet) {
			clientID := "unknown"
			if cl != nil {
				clientID = cl.ID
			}
			if cl == nil {
				logger.Debug("relay mqtt callback without client context", "topic", pk.TopicName)
			}
			if pk.TopicName == "" {
				logger.Warn("relay mqtt callback empty topic", "client_id", clientID)
				return
			}
			if r.isRecentNATSEcho(pk.TopicName, pk.Payload) {
				logger.Debug("relay skipping echoed NATS->MQTT message", "topic", pk.TopicName, "bytes", len(pk.Payload))
				return
			}
			subject, ok := r.mapper.mqttToNATS(pk.TopicName)
			if !ok {
				logger.Warn("relay mqtt topic rejected by mapper", "client_id", clientID, "topic", pk.TopicName)
				return
			}
			logger.Debug("relay bridge MQTT->NATS", "client_id", clientID, "topic", pk.TopicName, "subject", subject, "bytes", len(pk.Payload))
			msg := &nats.Msg{
				Subject: subject,
				Data:    append([]byte(nil), pk.Payload...),
				Header:  nats.Header{},
			}
			msg.Header.Set(r.cfg.Bridge.OriginHeader, mqttOriginValue)
			if err := r.nc.PublishMsg(msg); err != nil {
				logger.Error("relay publish MQTT->NATS failed", err, "topic", pk.TopicName, "subject", subject)
			}
		}); err != nil {
			return fmt.Errorf("subscribe mqtt inline filter %s: %w", filter, err)
		}
	}
	return nil
}

func (r *Runtime) publishPresence(peerID string, status sdkprotocol.PresenceStatus) {
	if !r.cfg.Presence.EmitConnectDisconnect {
		return
	}
	event := sdkprotocol.PresenceEvent{
		PeerID:         peerID,
		Status:         status,
		Transport:      sdkprotocol.TransportTypeMQTT,
		LastSeenUnixMs: time.Now().UTC().UnixMilli(),
	}
	if status == sdkprotocol.PresenceStatusOnline {
		event.ConnectionID = "mqtt:" + peerID
	}
	raw, err := json.Marshal(event)
	if err != nil {
		logger.Error("relay marshal presence failed", err, "peer_id", peerID)
		return
	}
	subject := r.mapper.natsPresenceSubject(peerID)
	if err := r.nc.Publish(subject, raw); err != nil {
		logger.Error("relay publish presence failed", err, "subject", subject, "peer_id", peerID)
	}
}

type relayHook struct {
	mqtt.HookBase
	runtime *Runtime
}

func (h *relayHook) ID() string {
	return "mpcium-relay"
}

func (h *relayHook) Provides(b byte) bool {
	supported := []byte{mqtt.OnConnectAuthenticate, mqtt.OnACLCheck, mqtt.OnSessionEstablished, mqtt.OnDisconnect}
	for _, item := range supported {
		if item == b {
			return true
		}
	}
	return false
}

func (h *relayHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	if cl == nil {
		return false
	}
	username := string(pk.Connect.Username)
	password := string(pk.Connect.Password)
	if username == "" || username != cl.ID {
		logger.Warn("relay mqtt auth rejected", "client_id", cl.ID, "reason", "username must equal client_id")
		return false
	}
	ok := h.runtime.credentials.check(username, password)
	if !ok {
		logger.Warn("relay mqtt auth rejected", "client_id", cl.ID, "reason", "bad username or password")
	}
	return ok
}

func (h *relayHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	if cl == nil {
		return false
	}
	if write {
		allowed := h.runtime.mapper.allowMQTTWrite(topic)
		logger.Debug("relay mqtt acl check", "client_id", cl.ID, "write", true, "topic", topic, "allowed", allowed)
		return allowed
	}
	allowed := h.runtime.mapper.allowMQTTRead(cl.ID, topic)
	logger.Debug("relay mqtt acl check", "client_id", cl.ID, "write", false, "topic", topic, "allowed", allowed)
	return allowed
}

func (h *relayHook) OnConnect(cl *mqtt.Client, _ packets.Packet) error {
	// Keep hook for compatibility, but only treat a client as online after
	// session establishment to avoid logging "connected" on auth failures.
	return nil
}

func (h *relayHook) OnSessionEstablished(cl *mqtt.Client, _ packets.Packet) {
	if cl == nil || cl.ID == mqtt.InlineClientId {
		return
	}
	h.runtime.publishPresence(cl.ID, sdkprotocol.PresenceStatusOnline)
	logger.Info("relay mqtt client connected", "client_id", cl.ID)
}

func (h *relayHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	if cl == nil || cl.ID == mqtt.InlineClientId {
		return
	}
	h.runtime.publishPresence(cl.ID, sdkprotocol.PresenceStatusOffline)
	logger.Info("relay mqtt client disconnected", "client_id", cl.ID, "expire", expire)
}

func connectNATS(cfg NATSConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	if cfg.Username != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	if cfg.TLS != nil {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	return nc, nil
}

func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		caPem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read nats ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPem); !ok {
			return nil, fmt.Errorf("parse nats ca cert")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, fmt.Errorf("both nats tls client_cert and client_key are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load nats client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func echoKey(topic string, payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%s|%x", topic, sum[:])
}

func (r *Runtime) markNATSEcho(topic string, payload []byte) {
	key := echoKey(topic, payload)
	now := time.Now()
	r.echoMu.Lock()
	r.recentEcho[key] = now
	// Best-effort cleanup of stale markers.
	for k, ts := range r.recentEcho {
		if now.Sub(ts) > 3*time.Second {
			delete(r.recentEcho, k)
		}
	}
	r.echoMu.Unlock()
}

func (r *Runtime) isRecentNATSEcho(topic string, payload []byte) bool {
	key := echoKey(topic, payload)
	now := time.Now()
	r.echoMu.Lock()
	defer r.echoMu.Unlock()
	ts, ok := r.recentEcho[key]
	if !ok {
		return false
	}
	if now.Sub(ts) > 3*time.Second {
		delete(r.recentEcho, key)
		return false
	}
	delete(r.recentEcho, key)
	return true
}
