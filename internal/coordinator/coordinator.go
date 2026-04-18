package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/google/uuid"
)

type Coordinator struct {
	id                string
	signer            Signer
	eventVerifier     SessionEventVerifier
	store             *MemorySessionStore
	keyInfoStore      *MemoryKeyInfoStore
	presence          PresenceView
	controls          ControlPublisher
	results           ResultPublisher
	defaultSessionTTL time.Duration
	now               func() time.Time
}

func NewCoordinator(cfg CoordinatorConfig) (*Coordinator, error) {
	cfg = applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Coordinator{
		id:                cfg.CoordinatorID,
		signer:            cfg.Signer,
		eventVerifier:     cfg.EventVerifier,
		store:             cfg.Store,
		keyInfoStore:      cfg.KeyInfoStore,
		presence:          cfg.Presence,
		controls:          cfg.Controls,
		results:           cfg.Results,
		defaultSessionTTL: cfg.DefaultSessionTTL,
		now:               cfg.Now,
	}, nil
}

func (c *Coordinator) HandleRequest(ctx context.Context, op Operation, raw []byte) ([]byte, error) {
	if op == OperationReshare {
		return reject(ErrorCodeUnsupported, "reshare is unsupported in this runtime version"), nil
	}
	req, err := parseRequest(raw)
	if err != nil {
		return reject(ErrorCodeInvalidJSON, "invalid JSON request"), nil
	}
	// Backward compatibility: keygen without protocol means dispatch both ECDSA and EdDSA sessions.
	if op == OperationKeygen && req.SessionStart != nil && isProtocolUnspecified(req.SessionStart.Protocol) {
		protocols := []sdkprotocol.ProtocolType{sdkprotocol.ProtocolTypeECDSA, sdkprotocol.ProtocolTypeEdDSA}
		sessionIDs := make([]string, 0, len(protocols))
		var firstAccepted *sdkprotocol.RequestAccepted
		var firstErr error

		for _, protocol := range protocols {
			cloned := cloneSessionStart(req.SessionStart)
			cloned.Protocol = protocol
			accepted, err := c.acceptRequest(ctx, op, &sdkprotocol.ControlMessage{SessionStart: cloned})
			if err != nil {
				var coordErr *CoordinatorError
				if AsCoordinatorError(err, &coordErr) && coordErr.Code == ErrorCodeConflict {
					// Allow fanout to continue: one protocol might already exist while the other doesn't.
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				return rejectFromError(err), nil
			}
			sessionIDs = append(sessionIDs, accepted.SessionID)
			if firstAccepted == nil {
				firstAccepted = accepted
			}
		}
		if firstAccepted == nil {
			if firstErr != nil {
				return rejectFromError(firstErr), nil
			}
			return reject(ErrorCodeConflict, "no keygen sessions created"), nil
		}

		logger.Info("coordinator expanded keygen request without protocol",
			"operation", string(op),
			"sessions", strings.Join(sessionIDs, ","),
		)
		return json.Marshal(firstAccepted)
	}

	accepted, err := c.acceptRequest(ctx, op, req)
	if err != nil {
		return rejectFromError(err), nil
	}
	return json.Marshal(accepted)
}

func (c *Coordinator) acceptRequest(ctx context.Context, op Operation, req *sdkprotocol.ControlMessage) (*sdkprotocol.RequestAccepted, error) {
	if err := c.validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	now := c.now()
	sessionID := "sess_" + uuid.NewString()
	start := cloneSessionStart(req.SessionStart)
	start.SessionID = sessionID
	start.Operation = op.ToSDK()

	participants := cloneParticipants(start.Participants)
	states := make(map[string]*ParticipantState, len(participants))
	keys := make(map[string][]byte, len(participants))
	for _, participant := range participants {
		states[participant.ParticipantID] = &ParticipantState{}
		keys[participant.ParticipantID] = append([]byte(nil), participant.IdentityPublicKey...)
	}

	session := &Session{
		ID:               sessionID,
		RequestID:        "req_" + uuid.NewString(),
		Op:               op,
		State:            SessionCreated,
		Start:            start,
		Participants:     participants,
		ParticipantState: states,
		ExchangeID:       "kx_" + uuid.NewString(),
		CreatedAt:        now,
		UpdatedAt:        now,
		ExpiresAt:        now.Add(c.defaultSessionTTL),
		ParticipantKeys:  keys,
	}
	if err := c.store.Create(ctx, session); err != nil {
		return nil, err
	}
	logger.Info("coordinator accepted request",
		"action", string(op),
		"protocol", string(start.Protocol),
		"session_id", session.ID,
		"participant_count", len(session.Participants),
		"wallet_id", keygenWalletID(start),
	)

	if err := c.fanOutSessionStart(ctx, session); err != nil {
		_ = c.failSession(ctx, session, ErrorCodeInternal, err.Error())
		return nil, newCoordinatorError(ErrorCodeInternal, "failed to publish session start")
	}
	session.State = SessionWaitingParticipants
	session.UpdatedAt = c.now()
	if err := c.store.Save(ctx, session); err != nil {
		return nil, newCoordinatorError(ErrorCodeInternal, "failed to save session")
	}

	return &sdkprotocol.RequestAccepted{
		Accepted:  true,
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func (c *Coordinator) HandleSessionEvent(ctx context.Context, raw []byte) error {
	var event sdkprotocol.SessionEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return newCoordinatorError(ErrorCodeInvalidJSON, "invalid JSON session event")
	}
	if err := validateSessionEventCompat(&event); err != nil {
		return newCoordinatorError(ErrorCodeValidation, err.Error())
	}

	session, ok := c.store.Get(ctx, event.SessionID)
	if !ok {
		return newCoordinatorError(ErrorCodeValidation, "unknown session")
	}
	if session.State.Terminal() {
		return nil
	}
	state, ok := session.ParticipantState[event.ParticipantID]
	if !ok {
		return newCoordinatorError(ErrorCodeValidation, "event sender is not a session participant")
	}
	if event.Sequence <= state.LastSequence {
		return newCoordinatorError(ErrorCodeValidation, "replayed session event sequence")
	}
	if c.eventVerifier != nil {
		if err := c.eventVerifier.VerifySessionEvent(ctx, session, &event); err != nil {
			return err
		}
	}
	state.LastSequence = event.Sequence

	switch {
	case event.PeerJoined != nil:
		state.Joined = true
	case event.PeerReady != nil:
		state.Ready = true
	case event.PeerKeyExchangeDone != nil:
		if session.State != SessionKeyExchange {
			return newCoordinatorError(ErrorCodeInvalidTransition, "key exchange done outside key exchange state")
		}
		state.KeyExchangeDone = true
	case event.SessionCompleted != nil:
		if session.State != SessionActiveMPC {
			return newCoordinatorError(ErrorCodeInvalidTransition, "completion outside active MPC state")
		}
		state.Completed = true
		if event.SessionCompleted.Result == nil {
			return c.failSession(ctx, session, ErrorCodeValidation, "missing result payload")
		}
		state.ResultHash = canonicalOperationResultHash(session.Op, event.SessionCompleted.Result)
	case event.PeerFailed != nil:
		state.Failed = true
		state.ErrorCode = ErrorCodeParticipantFailed
		state.ErrorMessage = firstNonEmpty(event.PeerFailed.Detail, "participant failed")
		return c.failSession(ctx, session, state.ErrorCode, state.ErrorMessage)
	case event.SessionFailed != nil:
		state.Failed = true
		state.ErrorCode = ErrorCodeParticipantFailed
		state.ErrorMessage = firstNonEmpty(event.SessionFailed.Detail, "session failed")
		return c.failSession(ctx, session, state.ErrorCode, state.ErrorMessage)
	default:
		return newCoordinatorError(ErrorCodeValidation, "unsupported session event type")
	}

	session.UpdatedAt = c.now()
	if err := c.advance(ctx, session, &event); err != nil {
		return err
	}
	logger.Debug("coordinator processed session event",
		"session_id", session.ID,
		"participant_id", event.ParticipantID,
		"state", string(session.State),
	)
	return c.store.Save(ctx, session)
}

func validateSessionEventCompat(event *sdkprotocol.SessionEvent) error {
	if event == nil {
		return sdkprotocol.ValidateSessionEvent(event)
	}
	if err := sdkprotocol.ValidateSessionEvent(event); err == nil {
		return nil
	}
	// Compatibility: allow keygen completion events without share_blob.
	if event.SessionCompleted == nil || event.SessionCompleted.Result == nil || event.SessionCompleted.Result.KeyShare == nil || len(event.SessionCompleted.Result.KeyShare.ShareBlob) > 0 {
		return sdkprotocol.ValidateSessionEvent(event)
	}
	clone := cloneSessionEventForValidation(event)
	clone.SessionCompleted.Result.KeyShare.ShareBlob = []byte{0}
	return sdkprotocol.ValidateSessionEvent(clone)
}

func cloneSessionEventForValidation(event *sdkprotocol.SessionEvent) *sdkprotocol.SessionEvent {
	clone := *event
	if event.SessionCompleted != nil {
		completed := *event.SessionCompleted
		clone.SessionCompleted = &completed
		if event.SessionCompleted.Result != nil {
			result := *event.SessionCompleted.Result
			clone.SessionCompleted.Result = &result
			if event.SessionCompleted.Result.KeyShare != nil {
				keyShare := *event.SessionCompleted.Result.KeyShare
				keyShare.PublicKey = append([]byte(nil), event.SessionCompleted.Result.KeyShare.PublicKey...)
				keyShare.ShareBlob = append([]byte(nil), event.SessionCompleted.Result.KeyShare.ShareBlob...)
				clone.SessionCompleted.Result.KeyShare = &keyShare
			}
		}
	}
	return &clone
}

func (c *Coordinator) Tick(ctx context.Context) (int, error) {
	now := c.now()
	expired := 0
	for _, session := range c.store.ListActive(ctx) {
		if !now.Before(session.ExpiresAt) {
			if err := c.expireSession(ctx, session); err != nil {
				return expired, err
			}
			expired++
		}
	}
	return expired, nil
}

func parseRequest(raw []byte) (*sdkprotocol.ControlMessage, error) {
	var msg sdkprotocol.ControlMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (c *Coordinator) validateRequest(ctx context.Context, op Operation, msg *sdkprotocol.ControlMessage) error {
	if msg == nil || msg.SessionStart == nil {
		return newCoordinatorError(ErrorCodeValidation, "session_start is required")
	}
	start := msg.SessionStart
	if isProtocolUnspecified(start.Protocol) {
		return newCoordinatorError(ErrorCodeValidation, "protocol is required")
	}
	start.SessionID = "tmp"
	start.Operation = op.ToSDK()
	if err := sdkprotocol.ValidateSessionStart(start); err != nil {
		return newCoordinatorError(ErrorCodeValidation, err.Error())
	}
	if start.Operation != op.ToSDK() {
		return newCoordinatorError(ErrorCodeValidation, "operation mismatch between subject and payload")
	}
	for _, participant := range start.Participants {
		if string(participant.PartyKey) != participant.ParticipantID {
			return newCoordinatorError(ErrorCodeValidation, "party_key must equal participant_id bytes")
		}
		if !c.presence.IsOnline(ctx, participant.ParticipantID) {
			return newCoordinatorError(ErrorCodeUnavailable, fmt.Sprintf("participant %q is offline", participant.ParticipantID))
		}
	}
	if op == OperationKeygen && c.keyInfoStore != nil {
		walletID := keygenWalletID(start)
		if walletID == "" {
			return newCoordinatorError(ErrorCodeValidation, "wallet_id is required")
		}
		protocol := string(start.Protocol)
		if _, exists := c.keyInfoStore.Get(walletID, protocol); exists {
			return newCoordinatorError(ErrorCodeConflict, "wallet key already exists")
		}
	}
	return nil
}

func isProtocolUnspecified(protocol sdkprotocol.ProtocolType) bool {
	return protocol == sdkprotocol.ProtocolTypeUnspecified || string(protocol) == ""
}

func (c *Coordinator) advance(ctx context.Context, session *Session, event *sdkprotocol.SessionEvent) error {
	switch session.State {
	case SessionWaitingParticipants:
		if allParticipants(session, func(p *ParticipantState) bool { return p.Joined && p.Ready }) {
			if err := c.fanOutKeyExchangeBegin(ctx, session); err != nil {
				return err
			}
			session.State = SessionKeyExchange
		}
	case SessionKeyExchange:
		if allParticipants(session, func(p *ParticipantState) bool { return p.KeyExchangeDone }) {
			if err := c.fanOutMPCBegin(ctx, session); err != nil {
				return err
			}
			session.State = SessionActiveMPC
		}
	case SessionActiveMPC:
		if allParticipants(session, func(p *ParticipantState) bool { return p.Completed }) {
			result, resultHash, err := c.buildCompletedResult(session, event)
			if err != nil {
				return c.failSession(ctx, session, ErrorCodeResultHashMismatch, err.Error())
			}
			if err := c.persistKeyInfoIfNeeded(session, result); err != nil {
				return c.failSession(ctx, session, ErrorCodeInternal, err.Error())
			}
			now := c.now()
			session.State = SessionCompleted
			session.ResultHash = resultHash
			session.Result = result
			session.CompletedAt = &now
			session.UpdatedAt = now
			if err := c.store.Save(ctx, session); err != nil {
				return err
			}
			return c.results.PublishResult(ctx, session.ID, result)
		}
	}
	return nil
}

func (c *Coordinator) persistKeyInfoIfNeeded(session *Session, result *sdkprotocol.Result) error {
	if c.keyInfoStore == nil || session == nil || result == nil || session.Op != OperationKeygen || result.KeyShare == nil {
		return nil
	}
	walletID := result.KeyShare.KeyID
	if walletID == "" {
		walletID = keygenWalletID(session.Start)
	}
	if walletID == "" {
		return fmt.Errorf("missing wallet id in keygen result")
	}
	participantIDs := make([]string, 0, len(session.Participants))
	for _, participant := range session.Participants {
		if participant == nil || participant.ParticipantID == "" {
			continue
		}
		participantIDs = append(participantIDs, participant.ParticipantID)
	}
	sort.Strings(participantIDs)
	info := KeyInfo{
		WalletID:     walletID,
		KeyType:      string(session.Start.Protocol),
		Threshold:    int(session.Start.Threshold),
		Participants: participantIDs,
		PublicKey:    append([]byte(nil), result.KeyShare.PublicKey...),
		CreatedAt:    c.now().UTC().Format(time.RFC3339Nano),
	}
	c.keyInfoStore.Save(info)
	return nil
}

func (c *Coordinator) fanOutSessionStart(ctx context.Context, session *Session) error {
	msg := &sdkprotocol.ControlMessage{
		SessionID:     session.ID,
		Sequence:      c.nextControlSequence(session),
		CoordinatorID: c.id,
		SessionStart:  cloneSessionStart(session.Start),
	}
	if err := SignControl(ctx, c.signer, msg); err != nil {
		return err
	}
	for _, participant := range session.Participants {
		if err := c.controls.PublishControl(ctx, participant.ParticipantID, msg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) fanOutKeyExchangeBegin(ctx context.Context, session *Session) error {
	msg := &sdkprotocol.ControlMessage{
		SessionID:     session.ID,
		Sequence:      c.nextControlSequence(session),
		CoordinatorID: c.id,
		KeyExchange:   &sdkprotocol.KeyExchangeBegin{ExchangeID: session.ExchangeID},
	}
	if err := SignControl(ctx, c.signer, msg); err != nil {
		return err
	}
	for _, participant := range session.Participants {
		if err := c.controls.PublishControl(ctx, participant.ParticipantID, msg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) fanOutMPCBegin(ctx context.Context, session *Session) error {
	msg := &sdkprotocol.ControlMessage{
		SessionID:     session.ID,
		Sequence:      c.nextControlSequence(session),
		CoordinatorID: c.id,
		MPCBegin:      &sdkprotocol.MPCBegin{},
	}
	if err := SignControl(ctx, c.signer, msg); err != nil {
		return err
	}
	for _, participant := range session.Participants {
		if err := c.controls.PublishControl(ctx, participant.ParticipantID, msg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) failSession(ctx context.Context, session *Session, code, message string) error {
	logger.Error("coordinator failing session",
		fmt.Errorf("%s: %s", code, message),
		"session_id", session.ID,
		"error_code", code,
	)
	now := c.now()
	session.State = SessionFailed
	session.ErrorCode = code
	session.ErrorMessage = message
	session.UpdatedAt = now
	session.CompletedAt = &now
	abort := &sdkprotocol.ControlMessage{
		SessionID:     session.ID,
		Sequence:      c.nextControlSequence(session),
		CoordinatorID: c.id,
		SessionAbort:  &sdkprotocol.SessionAbort{Reason: sdkprotocol.FailureReasonAborted, Detail: message},
	}
	if err := SignControl(ctx, c.signer, abort); err != nil {
		return err
	}
	for _, participant := range session.Participants {
		if err := c.controls.PublishControl(ctx, participant.ParticipantID, abort); err != nil {
			return err
		}
	}
	if err := c.store.Save(ctx, session); err != nil {
		return err
	}
	return c.results.PublishResult(ctx, session.ID, nil)
}

func (c *Coordinator) expireSession(ctx context.Context, session *Session) error {
	now := c.now()
	session.State = SessionExpired
	session.ErrorCode = ErrorCodeTimeout
	session.ErrorMessage = "session TTL expired"
	session.UpdatedAt = now
	session.CompletedAt = &now
	abort := &sdkprotocol.ControlMessage{
		SessionID:     session.ID,
		Sequence:      c.nextControlSequence(session),
		CoordinatorID: c.id,
		SessionAbort:  &sdkprotocol.SessionAbort{Reason: sdkprotocol.FailureReasonTimeout, Detail: session.ErrorMessage},
	}
	if err := SignControl(ctx, c.signer, abort); err != nil {
		return err
	}
	for _, participant := range session.Participants {
		if err := c.controls.PublishControl(ctx, participant.ParticipantID, abort); err != nil {
			return err
		}
	}
	if err := c.store.Save(ctx, session); err != nil {
		return err
	}
	return c.results.PublishResult(ctx, session.ID, nil)
}

func (c *Coordinator) buildCompletedResult(session *Session, event *sdkprotocol.SessionEvent) (*sdkprotocol.Result, string, error) {
	var resultHash string
	var result *sdkprotocol.Result
	for _, state := range session.ParticipantState {
		if state.ResultHash == "" {
			return nil, "", fmt.Errorf("participant completed without result hash")
		}
		if resultHash == "" {
			resultHash = state.ResultHash
			continue
		}
		if resultHash != state.ResultHash {
			return nil, "", fmt.Errorf("participant result hash mismatch")
		}
	}
	if event == nil || event.SessionCompleted == nil || event.SessionCompleted.Result == nil {
		return nil, "", fmt.Errorf("missing completion result")
	}
	in := event.SessionCompleted.Result
	switch session.Op {
	case OperationKeygen:
		if in.KeyShare == nil {
			return nil, "", fmt.Errorf("missing key share result")
		}
		result = &sdkprotocol.Result{
			KeyShare: &sdkprotocol.KeyShareResult{
				KeyID:     in.KeyShare.KeyID,
				PublicKey: append([]byte(nil), in.KeyShare.PublicKey...),
			},
		}
	case OperationSign:
		if in.Signature == nil {
			return nil, "", fmt.Errorf("missing signature result")
		}
		result = &sdkprotocol.Result{
			Signature: cloneResult(in).Signature,
		}
	default:
		return nil, "", fmt.Errorf("unsupported operation")
	}
	return result, canonicalResultHash(result), nil
}

func (c *Coordinator) nextControlSequence(session *Session) uint64 {
	session.ControlSeq++
	return session.ControlSeq
}

func allParticipants(session *Session, predicate func(*ParticipantState) bool) bool {
	for _, participant := range session.ParticipantState {
		if !predicate(participant) {
			return false
		}
	}
	return true
}

func canonicalOperationResultHash(op Operation, result *sdkprotocol.Result) string {
	if result == nil {
		return ""
	}
	switch op {
	case OperationKeygen:
		if result.KeyShare == nil {
			return ""
		}
		normalized := &sdkprotocol.Result{
			KeyShare: &sdkprotocol.KeyShareResult{
				KeyID:     result.KeyShare.KeyID,
				PublicKey: append([]byte(nil), result.KeyShare.PublicKey...),
			},
		}
		return canonicalResultHash(normalized)
	default:
		return canonicalResultHash(result)
	}
}

func canonicalResultHash(result *sdkprotocol.Result) string {
	if result == nil {
		return ""
	}
	raw, _ := json.Marshal(result)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func keygenWalletID(start *sdkprotocol.SessionStart) string {
	if start == nil || start.Keygen == nil {
		return ""
	}
	return start.Keygen.KeyID
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func reject(code, message string) []byte {
	raw, _ := json.Marshal(sdkprotocol.RequestRejected{
		Accepted:     false,
		ErrorCode:    code,
		ErrorMessage: message,
	})
	return raw
}

func rejectFromError(err error) []byte {
	var coordErr *CoordinatorError
	if ok := AsCoordinatorError(err, &coordErr); ok {
		return reject(coordErr.Code, coordErr.Message)
	}
	return reject(ErrorCodeInternal, err.Error())
}
