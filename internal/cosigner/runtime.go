package cosigner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium-sdk/participant"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium/pkg/logger"
)

type Runtime struct {
	cfg         Config
	relay       Relay
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

const bootstrapPreparamsSlot = "bootstrap"

func NewRuntime(cfg Config) (*Runtime, error) {
	relay, err := NewRelayFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	stores, err := newBadgerStores(cfg.DataDir, cfg.NodeID)
	if err != nil {
		relay.Close()
		return nil, err
	}
	identity, err := NewLocalIdentity(cfg.NodeID, cfg.IdentityPrivateKey)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	coordLookup, err := NewCoordinatorLookup(cfg.CoordinatorID, cfg.CoordinatorPublicKey)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	return &Runtime{
		cfg:         cfg,
		relay:       relay,
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
	if r.relay != nil {
		r.relay.Close()
	}
	if r.stores != nil {
		return r.stores.Close()
	}
	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
	logger.Info("cosigner runtime started", "node_id", r.cfg.NodeID, "identity_public_key_hex", hex.EncodeToString(r.identity.PublicKey()))
	if err := r.ensureECDSAPreparams(); err != nil {
		return err
	}
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
			r.publishPresenceOnShutdown()
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

func (r *Runtime) ensureECDSAPreparams() error {
	activeSlot, err := r.stores.LoadActivePreparamsSlot(sdkprotocol.ProtocolTypeECDSA)
	if err != nil {
		return fmt.Errorf("load active ecdsa preparams slot: %w", err)
	}
	if activeSlot != "" {
		existing, loadErr := r.stores.LoadPreparamsSlot(sdkprotocol.ProtocolTypeECDSA, activeSlot)
		if loadErr != nil {
			return fmt.Errorf("load ecdsa preparams slot %q: %w", activeSlot, loadErr)
		}
		if len(existing) > 0 {
			logger.Info("cosigner preparams ready", "protocol", "ecdsa", "source", "store", "slot", activeSlot)
			return nil
		}
		logger.Warn("active ecdsa preparams slot is empty; regenerating", "slot", activeSlot)
	}

	logger.Info("cosigner preparams missing; generating", "protocol", "ecdsa")
	startedAt := time.Now()
	preparams, err := ecdsaKeygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		return fmt.Errorf("generate ecdsa preparams: %w", err)
	}
	blob, err := encodeECDSAPreparams(preparams)
	if err != nil {
		return fmt.Errorf("encode ecdsa preparams: %w", err)
	}
	if err := r.stores.SavePreparamsSlot(sdkprotocol.ProtocolTypeECDSA, bootstrapPreparamsSlot, blob); err != nil {
		return fmt.Errorf("save ecdsa preparams slot %q: %w", bootstrapPreparamsSlot, err)
	}
	if err := r.stores.SaveActivePreparamsSlot(sdkprotocol.ProtocolTypeECDSA, bootstrapPreparamsSlot); err != nil {
		return fmt.Errorf("save active ecdsa preparams slot: %w", err)
	}
	logger.Info("cosigner preparams generated", "protocol", "ecdsa", "slot", bootstrapPreparamsSlot, "elapsed", time.Since(startedAt).Round(time.Millisecond))
	return nil
}

func encodeECDSAPreparams(data *ecdsaKeygen.LocalPreParams) ([]byte, error) {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (r *Runtime) subscribe() error {
	controlSub, err := r.relay.Subscribe(controlSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handleControl(raw); err != nil {
			logger.Error("handle control message failed", err)
		}
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, controlSub)

	p2pSub, err := r.relay.Subscribe(p2pWildcardSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handlePeer(raw); err != nil {
			logger.Error("handle peer message failed", err)
		}
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, p2pSub)

	return r.relay.Flush()
}

func (r *Runtime) handleControl(raw []byte) error {
	var msg sdkprotocol.ControlMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	if err := sdkprotocol.ValidateControlMessage(&msg); err != nil {
		if !hasControlBody(&msg) {
			logger.Warn("ignoring control message without body")
			return nil
		}
		logger.Error("invalid control message received", err,
			"node_id", r.cfg.NodeID,
			"session_id", msg.SessionID,
			"sequence", msg.Sequence,
			"coordinator_id", msg.CoordinatorID,
			"has_session_start", msg.SessionStart != nil,
			"has_key_exchange", msg.KeyExchange != nil,
			"has_mpc_begin", msg.MPCBegin != nil,
			"has_session_abort", msg.SessionAbort != nil,
			"raw_control_json", string(raw),
		)
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
	if msg.SessionAbort != nil {
		// Current SDK participant session doesn't handle SessionAbort control messages.
		// Treat abort as terminal, clean up local session state, and stop processing.
		logger.Warn("cosigner received session abort",
			"node_id", r.cfg.NodeID,
			"session_id", msg.SessionID,
			"reason", msg.SessionAbort.Reason,
			"detail", msg.SessionAbort.Detail,
		)
		logger.Info("cosigner session ended",
			"node_id", r.cfg.NodeID,
			"session_id", msg.SessionID,
			"outcome", "aborted",
			"reason", msg.SessionAbort.Reason,
		)
		r.dropSessionMeta(msg.SessionID)
		_ = r.stores.DeleteSessionArtifacts(msg.SessionID)
		return nil
	}
	actions, err := session.HandleControl(&msg)
	if err != nil {
		logger.Error("session handle control failed", err,
			"node_id", r.cfg.NodeID,
			"session_id", msg.SessionID,
			"sequence", msg.Sequence,
			"coordinator_id", msg.CoordinatorID,
			"control_type", controlType(&msg),
			"raw_control_json", string(raw),
		)
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
	for _, peerMsg := range actions.PeerMessages {
		raw, err := json.Marshal(peerMsg)
		if err != nil {
			return err
		}
		if err := r.relay.Publish(p2pSubject(peerMsg.ToParticipantID, peerMsg.SessionID), raw); err != nil {
			return err
		}
	}
	for _, event := range actions.SessionEvents {
		sanitized, err := sanitizeAndResignSessionEvent(event, r.cfg.IdentityPrivateKey)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(sanitized)
		if err != nil {
			return err
		}
		if err := r.relay.Publish(sessionEventSubject(sanitized.SessionID), raw); err != nil {
			return err
		}
	}
	if actions.Cleanup != nil && actions.Cleanup.DropArtifacts {
		outcome := "cleanup"
		if actions.Result != nil {
			switch {
			case actions.Result.KeyShare != nil:
				outcome = "completed_keygen"
			case actions.Result.Signature != nil:
				outcome = "completed_sign"
			}
		}
		logger.Info("cosigner session ended",
			"node_id", r.cfg.NodeID,
			"session_id", actions.Cleanup.SessionID,
			"outcome", outcome,
		)
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

func sanitizeSessionEvent(event *sdkprotocol.SessionEvent) *sdkprotocol.SessionEvent {
	if event == nil || event.SessionCompleted == nil || event.SessionCompleted.Result == nil || event.SessionCompleted.Result.KeyShare == nil {
		return event
	}
	clone := *event
	completed := *event.SessionCompleted
	result := *event.SessionCompleted.Result
	keyShare := *event.SessionCompleted.Result.KeyShare
	// Never publish secret share material over relay topics.
	keyShare.ShareBlob = nil
	result.KeyShare = &keyShare
	completed.Result = &result
	clone.SessionCompleted = &completed
	return &clone
}

func sanitizeAndResignSessionEvent(event *sdkprotocol.SessionEvent, privateKey []byte) (*sdkprotocol.SessionEvent, error) {
	sanitized := sanitizeSessionEvent(event)
	if sanitized == nil || sanitized == event {
		return event, nil
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity private key size: %d", len(privateKey))
	}
	payload, err := sdkprotocol.SessionEventSigningBytes(sanitized)
	if err != nil {
		return nil, err
	}
	sanitized.Signature = ed25519.Sign(ed25519.PrivateKey(privateKey), payload)
	return sanitized, nil
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
	transportType := r.relay.ProtocolType()
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
	return r.relay.Publish(presenceSubject(r.cfg.NodeID), raw)
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

func (r *Runtime) publishPresenceOnShutdown() {
	done := make(chan error, 1)
	go func() {
		done <- r.publishPresence(sdkprotocol.PresenceStatusOffline)
	}()
	select {
	case err := <-done:
		if err != nil {
			logger.Warn("failed to publish offline presence", "error", err)
		}
	case <-time.After(500 * time.Millisecond):
		logger.Warn("timed out publishing offline presence")
	}
}

func hasControlBody(msg *sdkprotocol.ControlMessage) bool {
	if msg == nil {
		return false
	}
	return msg.SessionStart != nil ||
		msg.KeyExchange != nil ||
		msg.MPCBegin != nil ||
		msg.SessionAbort != nil
}
