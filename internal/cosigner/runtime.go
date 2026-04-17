package cosigner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/vietddude/mpcium-sdk/participant"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type Runtime struct {
	cfg         Config
	transport   Transport
	stores      Stores
	identity    *localIdentity
	coordLookup *coordinatorLookup
	sessionsMu  sync.RWMutex
	sessions    map[string]*participant.ParticipantSession
	sessionMeta map[string]sessionMeta
	subs        []Subscription
}

type sessionMeta struct {
	protocol string
	action   string
}

func NewRuntime(cfg Config) (*Runtime, error) {
	transport, err := NewNATSTransport(cfg.NATSURL)
	if err != nil {
		return nil, err
	}
	return NewRuntimeWithTransport(cfg, transport)
}

func NewRuntimeWithTransport(cfg Config, transport Transport) (*Runtime, error) {
	if transport == nil {
		return nil, errors.New("transport is required")
	}
	stores, err := newBadgerStores(cfg.DataDir)
	if err != nil {
		transport.Close()
		return nil, err
	}
	identity, err := NewLocalIdentity(cfg.NodeID, cfg.IdentityPrivateKey)
	if err != nil {
		transport.Close()
		_ = stores.Close()
		return nil, err
	}
	coordLookup, err := NewCoordinatorLookup(cfg.CoordinatorID, cfg.CoordinatorPublicKey)
	if err != nil {
		transport.Close()
		_ = stores.Close()
		return nil, err
	}
	return &Runtime{
		cfg:         cfg,
		transport:   transport,
		stores:      stores,
		identity:    identity,
		coordLookup: coordLookup,
		sessions:    map[string]*participant.ParticipantSession{},
		sessionMeta: map[string]sessionMeta{},
	}, nil
}

func (r *Runtime) Close() error {
	for _, sub := range r.subs {
		_ = sub.Unsubscribe()
	}
	if r.transport != nil {
		r.transport.Close()
	}
	if r.stores != nil {
		return r.stores.Close()
	}
	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
	logger.Info("cosigner runtime started", "node_id", r.cfg.NodeID)
	if err := r.subscribe(); err != nil {
		return err
	}
	if err := r.publishPresence(sdkprotocol.PresenceStatusOnline); err != nil {
		return err
	}

	tick := time.NewTicker(r.cfg.TickInterval)
	defer tick.Stop()
	presence := time.NewTicker(r.cfg.PresenceInterval)
	defer presence.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("cosigner runtime stopping", "node_id", r.cfg.NodeID)
			_ = r.publishPresence(sdkprotocol.PresenceStatusOffline)
			return nil
		case <-tick.C:
			if err := r.tickSessions(); err != nil {
				return err
			}
		case <-presence.C:
			if err := r.publishPresence(sdkprotocol.PresenceStatusOnline); err != nil {
				return err
			}
		}
	}
}

func (r *Runtime) subscribe() error {
	controlSub, err := r.transport.Subscribe(controlSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handleControl(raw); err != nil {
			logger.Error("handle control message failed", err)
		}
	})
	if err != nil {
		return err
	}
	logger.Info("subscribed control subject", "subject", controlSubject(r.cfg.NodeID))
	r.subs = append(r.subs, controlSub)

	p2pSub, err := r.transport.Subscribe(p2pWildcardSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handlePeer(raw); err != nil {
			logger.Error("handle peer message failed", err)
		}
	})
	if err != nil {
		return err
	}
	logger.Info("subscribed p2p subject", "subject", p2pWildcardSubject(r.cfg.NodeID))
	r.subs = append(r.subs, p2pSub)

	return r.transport.Flush()
}

func (r *Runtime) handleControl(raw []byte) error {
	var msg sdkprotocol.ControlMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	if err := sdkprotocol.ValidateControlMessage(&msg); err != nil {
		return err
	}

	if msg.SessionStart != nil {
		meta := sessionMeta{
			protocol: protocolLabel(msg.SessionStart.Protocol),
			action:   actionLabel(msg.SessionStart.Operation),
		}
		logger.Info("cosigner received session start",
			"session_id", msg.SessionID,
			"action", meta.action,
		)
		return r.startSession(&msg, meta)
	}
	meta := r.getSessionMeta(msg.SessionID)
	logger.Debug("cosigner received control message",
		"node_id", r.cfg.NodeID,
		"session_id", msg.SessionID,
		"sequence", msg.Sequence,
		"control_type", controlType(&msg),
		"protocol", meta.protocol,
		"action", meta.action,
	)
	session := r.getSession(msg.SessionID)
	if session == nil {
		logger.Warn("ignoring control for unknown session", "session_id", msg.SessionID)
		return nil
	}
	actions, err := session.HandleControl(&msg)
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) startSession(msg *sdkprotocol.ControlMessage, meta sessionMeta) error {
	if len(r.sessions) >= r.cfg.MaxActiveSessions {
		return errors.New("max active sessions reached")
	}
	if err := r.verifyControlSignature(msg); err != nil {
		return err
	}
	peerKeys := make(map[string]ed25519.PublicKey, len(msg.SessionStart.Participants))
	for _, participantDef := range msg.SessionStart.Participants {
		if participantDef.ParticipantID == r.cfg.NodeID {
			continue
		}
		peerKeys[participantDef.ParticipantID] = append([]byte(nil), participantDef.IdentityPublicKey...)
	}
	sess, err := participant.New(participant.Config{
		Start:              msg.SessionStart,
		LocalParticipantID: r.cfg.NodeID,
		Identity:           r.identity,
		Peers:              NewPeerLookup(peerKeys),
		Coordinator:        r.coordLookup,
		Preparams:          r.stores,
		Shares:             r.stores,
		SessionArtifacts:   r.stores,
	})
	if err != nil {
		return err
	}
	r.sessionsMu.Lock()
	r.sessions[msg.SessionID] = sess
	r.sessionMeta[msg.SessionID] = meta
	r.sessionsMu.Unlock()
	logger.Info("cosigner started session", "session_id", msg.SessionID, "action", meta.action)

	actions, err := sess.Start()
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) handlePeer(raw []byte) error {
	var msg sdkprotocol.PeerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	logger.Debug("cosigner received peer message",
		"node_id", r.cfg.NodeID,
		"session_id", msg.SessionID,
		"from_participant", msg.FromParticipantID,
		"phase", string(msg.Phase),
	)
	session := r.getSession(msg.SessionID)
	if session == nil {
		logger.Warn("ignoring peer message for unknown session", "session_id", msg.SessionID)
		return nil
	}
	actions, err := session.HandlePeer(&msg)
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) tickSessions() error {
	r.sessionsMu.RLock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	r.sessionsMu.RUnlock()
	for _, id := range ids {
		session := r.getSession(id)
		if session == nil {
			continue
		}
		actions, err := session.Tick(time.Now())
		if err != nil {
			return err
		}
		if err := r.dispatchActions(actions); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) dispatchActions(actions participant.Actions) error {
	logger.Debug("dispatching actions", "actions", actions)
	for _, peerMsg := range actions.PeerMessages {
		raw, err := json.Marshal(peerMsg)
		if err != nil {
			return err
		}
		if err := r.transport.Publish(p2pSubject(peerMsg.ToParticipantID, peerMsg.SessionID), raw); err != nil {
			return err
		}
	}
	for _, event := range actions.SessionEvents {
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err := r.transport.Publish(sessionEventSubject(event.SessionID), raw); err != nil {
			return err
		}
	}
	if actions.Cleanup != nil && actions.Cleanup.DropArtifacts {
		r.dropSessionMeta(actions.Cleanup.SessionID)
		_ = r.stores.DeleteSessionArtifacts(actions.Cleanup.SessionID)
	}
	return nil
}

func (r *Runtime) getSessionMeta(sessionID string) sessionMeta {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	if meta, ok := r.sessionMeta[sessionID]; ok {
		return meta
	}
	return sessionMeta{protocol: "unknown", action: "unknown"}
}

func (r *Runtime) dropSessionMeta(sessionID string) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()
	delete(r.sessionMeta, sessionID)
	delete(r.sessions, sessionID)
}

func controlType(msg *sdkprotocol.ControlMessage) string {
	switch {
	case msg == nil:
		return "unknown"
	case msg.KeyExchange != nil:
		return "key_exchange_begin"
	case msg.MPCBegin != nil:
		return "mpc_begin"
	case msg.SessionAbort != nil:
		return "session_abort"
	case msg.SessionStart != nil:
		return "session_start"
	default:
		return "unknown"
	}
}

func protocolLabel(protocol sdkprotocol.ProtocolType) string {
	value := strings.TrimSpace(string(protocol))
	if value == "" || value == string(sdkprotocol.ProtocolTypeUnspecified) {
		return "unknown"
	}
	return strings.ToLower(value)
}

func actionLabel(operation sdkprotocol.OperationType) string {
	switch operation {
	case sdkprotocol.OperationTypeKeygen:
		return "keygen"
	case sdkprotocol.OperationTypeSign:
		return "sign"
	case sdkprotocol.OperationTypeReshare:
		return "reshare"
	default:
		return "unknown"
	}
}

func (r *Runtime) publishPresence(status sdkprotocol.PresenceStatus) error {
	transportType := r.transport.ProtocolType()
	connectionPrefix := strings.ToLower(string(transportType))
	if connectionPrefix == "" || transportType == sdkprotocol.TransportTypeUnspecified {
		connectionPrefix = "transport"
	}
	event := sdkprotocol.PresenceEvent{
		PeerID:         r.cfg.NodeID,
		Status:         status,
		Transport:      transportType,
		LastSeenUnixMs: time.Now().UTC().UnixMilli(),
	}
	if status == sdkprotocol.PresenceStatusOnline {
		event.ConnectionID = connectionPrefix + ":" + r.cfg.NodeID
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return r.transport.Publish(presenceSubject(r.cfg.NodeID), raw)
}

func (r *Runtime) getSession(sessionID string) *participant.ParticipantSession {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	return r.sessions[sessionID]
}

func (r *Runtime) verifyControlSignature(msg *sdkprotocol.ControlMessage) error {
	pub, err := r.coordLookup.LookupCoordinator(msg.CoordinatorID)
	if err != nil {
		return err
	}
	payload, err := sdkprotocol.ControlSigningBytes(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, msg.Signature) {
		return errors.New("invalid control signature")
	}
	return nil
}
