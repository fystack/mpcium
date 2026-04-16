package cosigner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/vietddude/mpcium-sdk/participant"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type Runtime struct {
	cfg         Config
	nc          *nats.Conn
	stores      *badgerStores
	identity    *localIdentity
	coordLookup *coordinatorLookup
	sessionsMu  sync.RWMutex
	sessions    map[string]*participant.ParticipantSession
	subs        []*nats.Subscription
}

func NewRuntime(cfg Config) (*Runtime, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("node_id is required")
	}
	if cfg.NATSURL == "" {
		return nil, errors.New("nats_url is required")
	}
	if cfg.CoordinatorID == "" || len(cfg.CoordinatorPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("valid coordinator key is required")
	}
	if len(cfg.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("valid identity private key is required")
	}
	if cfg.MaxActiveSessions <= 0 {
		cfg.MaxActiveSessions = 64
	}
	if cfg.PresenceInterval <= 0 {
		cfg.PresenceInterval = 5 * time.Second
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 100 * time.Millisecond
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	stores, err := newBadgerStores(cfg.DataDir)
	if err != nil {
		nc.Close()
		return nil, err
	}
	private := ed25519.PrivateKey(cfg.IdentityPrivateKey)
	public := private.Public().(ed25519.PublicKey)
	return &Runtime{
		cfg:      cfg,
		nc:       nc,
		stores:   stores,
		identity: &localIdentity{participantID: cfg.NodeID, publicKey: public, privateKey: private},
		coordLookup: &coordinatorLookup{keys: map[string]ed25519.PublicKey{
			cfg.CoordinatorID: append([]byte(nil), cfg.CoordinatorPublicKey...),
		}},
		sessions: map[string]*participant.ParticipantSession{},
	}, nil
}

func (r *Runtime) Close() error {
	for _, sub := range r.subs {
		_ = sub.Unsubscribe()
	}
	if r.nc != nil {
		r.nc.Close()
	}
	if r.stores != nil {
		return r.stores.Close()
	}
	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
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
	controlSub, err := r.nc.Subscribe(controlSubject(r.cfg.NodeID), func(msg *nats.Msg) {
		_ = r.handleControl(msg.Data)
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, controlSub)

	p2pSub, err := r.nc.Subscribe(p2pWildcardSubject(r.cfg.NodeID), func(msg *nats.Msg) {
		_ = r.handlePeer(msg.Data)
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, p2pSub)

	return r.nc.Flush()
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
		return r.startSession(&msg)
	}
	session := r.getSession(msg.SessionID)
	if session == nil {
		return fmt.Errorf("unknown session %s", msg.SessionID)
	}
	effects, err := session.HandleControl(&msg)
	if err != nil {
		return err
	}
	return r.publishEffects(effects)
}

func (r *Runtime) startSession(msg *sdkprotocol.ControlMessage) error {
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
		Peers:              &peerLookup{keys: peerKeys},
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
	r.sessionsMu.Unlock()

	effects, err := sess.Start()
	if err != nil {
		return err
	}
	return r.publishEffects(effects)
}

func (r *Runtime) handlePeer(raw []byte) error {
	var msg sdkprotocol.PeerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	session := r.getSession(msg.SessionID)
	if session == nil {
		return fmt.Errorf("unknown session %s", msg.SessionID)
	}
	effects, err := session.HandlePeer(&msg)
	if err != nil {
		return err
	}
	return r.publishEffects(effects)
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
		effects, err := session.Tick(time.Now())
		if err != nil {
			return err
		}
		if err := r.publishEffects(effects); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) publishEffects(effects participant.Effects) error {
	for _, peerMsg := range effects.PeerMessages {
		raw, err := json.Marshal(peerMsg)
		if err != nil {
			return err
		}
		if err := r.nc.Publish(p2pSubject(peerMsg.ToParticipantID, peerMsg.SessionID), raw); err != nil {
			return err
		}
	}
	for _, event := range effects.SessionEvents {
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err := r.nc.Publish(sessionEventSubject(event.SessionID), raw); err != nil {
			return err
		}
	}
	if effects.Cleanup != nil && effects.Cleanup.DropArtifacts {
		_ = r.stores.DeleteSessionArtifacts(effects.Cleanup.SessionID)
	}
	return nil
}

func (r *Runtime) publishPresence(status sdkprotocol.PresenceStatus) error {
	event := sdkprotocol.PresenceEvent{
		PeerID:         r.cfg.NodeID,
		Status:         status,
		Transport:      sdkprotocol.TransportTypeNATS,
		LastSeenUnixMs: time.Now().UTC().UnixMilli(),
	}
	if status == sdkprotocol.PresenceStatusOnline {
		event.ConnectionID = "nats:" + r.cfg.NodeID
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return r.nc.Publish(presenceSubject(r.cfg.NodeID), raw)
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
