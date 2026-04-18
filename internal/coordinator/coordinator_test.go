package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type fakeSigner struct{}

func (fakeSigner) Sign(context.Context, []byte) ([]byte, error) { return []byte("sig"), nil }

type fakeControlPublisher struct {
	published map[string][]*sdkprotocol.ControlMessage
}

func (p *fakeControlPublisher) PublishControl(_ context.Context, participantID string, control *sdkprotocol.ControlMessage) error {
	if p.published == nil {
		p.published = map[string][]*sdkprotocol.ControlMessage{}
	}
	cloned := *control
	p.published[participantID] = append(p.published[participantID], &cloned)
	return nil
}

type fakeResultPublisher struct {
	results map[string]*sdkprotocol.Result
}

func (p *fakeResultPublisher) PublishResult(_ context.Context, sessionID string, result *sdkprotocol.Result) error {
	if p.results == nil {
		p.results = map[string]*sdkprotocol.Result{}
	}
	p.results[sessionID] = result
	return nil
}

func TestTopicHelpersMatchRuntimeNamespace(t *testing.T) {
	if got := RequestSubject(OperationKeygen); got != "mpc.v1.request.keygen" {
		t.Fatalf("RequestSubject() = %q", got)
	}
	if got := PeerControlSubject("peer-node-01"); got != "mpc.v1.peer.peer-node-01.control" {
		t.Fatalf("PeerControlSubject() = %q", got)
	}
	if got := SessionEventSubject("sess_123"); got != "mpc.v1.session.sess_123.event" {
		t.Fatalf("SessionEventSubject() = %q", got)
	}
	if got := SessionResultSubject("sess_123"); got != "mpc.v1.session.sess_123.result" {
		t.Fatalf("SessionResultSubject() = %q", got)
	}
}

func TestHandleRequestAcceptsAndFansOutSessionStart(t *testing.T) {
	coord, controls, _, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	req := &sdkprotocol.ControlMessage{
		SessionStart: newSessionStart(fixtures),
	}
	rawReply, err := coord.HandleRequest(context.Background(), OperationSign, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var reply sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawReply, &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Accepted || reply.SessionID == "" {
		t.Fatalf("unexpected reply: %+v", reply)
	}
	if len(controls.published["p1"]) == 0 || controls.published["p1"][0].SessionStart == nil {
		t.Fatalf("missing session start fanout")
	}
}

func TestHandleRequestRejectsOfflineParticipant(t *testing.T) {
	coord, _, _, fixtures := newTestCoordinator(t)
	_ = fixtures
	req := &sdkprotocol.ControlMessage{SessionStart: newSessionStart(fixtures)}
	rawReply, err := coord.HandleRequest(context.Background(), OperationSign, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var reply sdkprotocol.RequestRejected
	if err := json.Unmarshal(rawReply, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Accepted {
		t.Fatalf("expected rejection")
	}
	if reply.ErrorCode != ErrorCodeUnavailable {
		t.Fatalf("error code = %s, want %s", reply.ErrorCode, ErrorCodeUnavailable)
	}
	if reply.ErrorMessage != `participant "p1" is offline` {
		t.Fatalf("error message = %q", reply.ErrorMessage)
	}
}

func TestLifecycleCompletesSignAndPublishesResult(t *testing.T) {
	ctx := context.Background()
	coord, _, results, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	req := &sdkprotocol.ControlMessage{SessionStart: newSessionStart(fixtures)}
	rawReply, err := coord.HandleRequest(ctx, OperationSign, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var reply sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawReply, &reply); err != nil {
		t.Fatal(err)
	}

	signResult := &sdkprotocol.Result{Signature: &sdkprotocol.SignatureResult{KeyID: "k", Signature: []byte("sig")}}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerJoined: &sdkprotocol.PeerJoined{ParticipantID: participant}})
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerReady: &sdkprotocol.PeerReady{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerKeyExchangeDone: &sdkprotocol.PeerKeyExchangeDone{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{SessionCompleted: &sdkprotocol.SessionCompleted{Result: signResult}})
	}

	result := results.results[reply.SessionID]
	if result == nil || result.Signature == nil {
		t.Fatalf("missing published sign result")
	}
}

func TestLifecycleCompletesKeygenWithoutShareBlob(t *testing.T) {
	ctx := context.Background()
	coord, _, results, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	keygenReq := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID: "client-supplied",
			Protocol:  sdkprotocol.ProtocolTypeEdDSA,
			Operation: sdkprotocol.OperationTypeKeygen,
			Threshold: 1,
			Participants: []*sdkprotocol.SessionParticipant{
				{ParticipantID: "p1", PartyKey: []byte("p1"), IdentityPublicKey: fixtures["p1"].pub},
				{ParticipantID: "p2", PartyKey: []byte("p2"), IdentityPublicKey: fixtures["p2"].pub},
			},
			Keygen: &sdkprotocol.KeygenPayload{KeyID: "wallet_demo_001"},
		},
	}
	rawReply, err := coord.HandleRequest(ctx, OperationKeygen, mustJSON(t, keygenReq))
	if err != nil {
		t.Fatal(err)
	}
	var reply sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawReply, &reply); err != nil {
		t.Fatal(err)
	}

	result := &sdkprotocol.Result{
		KeyShare: &sdkprotocol.KeyShareResult{
			KeyID:     "wallet_demo_001",
			PublicKey: []byte("pub"),
		},
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerJoined: &sdkprotocol.PeerJoined{ParticipantID: participant}})
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerReady: &sdkprotocol.PeerReady{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerKeyExchangeDone: &sdkprotocol.PeerKeyExchangeDone{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, reply.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{SessionCompleted: &sdkprotocol.SessionCompleted{Result: result}})
	}

	published := results.results[reply.SessionID]
	if published == nil || published.KeyShare == nil {
		t.Fatalf("missing published keygen result")
	}
	if len(published.KeyShare.ShareBlob) != 0 {
		t.Fatalf("share blob should not be required/published")
	}
}

func TestHandleRequestRejectsDuplicateWalletIDAfterCompletedKeygen(t *testing.T) {
	ctx := context.Background()
	coord, _, _, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	requestForWallet := func(walletID string, protocol sdkprotocol.ProtocolType) *sdkprotocol.ControlMessage {
		return &sdkprotocol.ControlMessage{
			SessionStart: &sdkprotocol.SessionStart{
				SessionID: "client-supplied",
				Protocol:  protocol,
				Operation: sdkprotocol.OperationTypeKeygen,
				Threshold: 1,
				Participants: []*sdkprotocol.SessionParticipant{
					{ParticipantID: "p1", PartyKey: []byte("p1"), IdentityPublicKey: fixtures["p1"].pub},
					{ParticipantID: "p2", PartyKey: []byte("p2"), IdentityPublicKey: fixtures["p2"].pub},
				},
				Keygen: &sdkprotocol.KeygenPayload{KeyID: walletID},
			},
		}
	}

	rawReply, err := coord.HandleRequest(ctx, OperationKeygen, mustJSON(t, requestForWallet("wallet_demo_001", sdkprotocol.ProtocolTypeEdDSA)))
	if err != nil {
		t.Fatal(err)
	}
	var accepted sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawReply, &accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted || accepted.SessionID == "" {
		t.Fatalf("unexpected keygen accepted reply: %+v", accepted)
	}

	keygenResult := &sdkprotocol.Result{
		KeyShare: &sdkprotocol.KeyShareResult{
			KeyID:     "wallet_demo_001",
			PublicKey: []byte("pub"),
		},
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, accepted.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerJoined: &sdkprotocol.PeerJoined{ParticipantID: participant}})
		emitSignedEvent(t, coord, accepted.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerReady: &sdkprotocol.PeerReady{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, accepted.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{PeerKeyExchangeDone: &sdkprotocol.PeerKeyExchangeDone{ParticipantID: participant}})
	}
	for _, participant := range []string{"p1", "p2"} {
		emitSignedEvent(t, coord, accepted.SessionID, fixtures, participant, &sdkprotocol.SessionEvent{SessionCompleted: &sdkprotocol.SessionCompleted{Result: keygenResult}})
	}

	rawDupReply, err := coord.HandleRequest(ctx, OperationKeygen, mustJSON(t, requestForWallet("wallet_demo_001", sdkprotocol.ProtocolTypeEdDSA)))
	if err != nil {
		t.Fatal(err)
	}
	var rejected sdkprotocol.RequestRejected
	if err := json.Unmarshal(rawDupReply, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Accepted {
		t.Fatalf("expected duplicate keygen request to be rejected")
	}
	if rejected.ErrorCode != ErrorCodeConflict {
		t.Fatalf("error code = %s, want %s", rejected.ErrorCode, ErrorCodeConflict)
	}

	rawOtherProtocolReply, err := coord.HandleRequest(ctx, OperationKeygen, mustJSON(t, requestForWallet("wallet_demo_001", sdkprotocol.ProtocolTypeECDSA)))
	if err != nil {
		t.Fatal(err)
	}
	var acceptedOtherProtocol sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawOtherProtocolReply, &acceptedOtherProtocol); err != nil {
		t.Fatal(err)
	}
	if !acceptedOtherProtocol.Accepted {
		t.Fatalf("expected same wallet id with different protocol to be accepted")
	}
}

func TestHandleRequestKeygenWithoutProtocolCreatesBothSessions(t *testing.T) {
	ctx := context.Background()
	coord, _, _, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	req := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID: "client-supplied",
			Protocol:  sdkprotocol.ProtocolTypeUnspecified,
			Operation: sdkprotocol.OperationTypeKeygen,
			Threshold: 1,
			Participants: []*sdkprotocol.SessionParticipant{
				{ParticipantID: "p1", PartyKey: []byte("p1"), IdentityPublicKey: fixtures["p1"].pub},
				{ParticipantID: "p2", PartyKey: []byte("p2"), IdentityPublicKey: fixtures["p2"].pub},
			},
			Keygen: &sdkprotocol.KeygenPayload{KeyID: "wallet_dual_protocol"},
		},
	}

	rawReply, err := coord.HandleRequest(ctx, OperationKeygen, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var accepted sdkprotocol.RequestAccepted
	if err := json.Unmarshal(rawReply, &accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted {
		t.Fatalf("expected request accepted")
	}
	active := coord.store.ListActive(ctx)
	if len(active) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(active))
	}
	seenProtocols := map[sdkprotocol.ProtocolType]bool{}
	for _, session := range active {
		seenProtocols[session.Start.Protocol] = true
	}
	if !seenProtocols[sdkprotocol.ProtocolTypeECDSA] || !seenProtocols[sdkprotocol.ProtocolTypeEdDSA] {
		t.Fatalf("expected both ECDSA and EdDSA sessions, got %+v", seenProtocols)
	}
}

func TestHandleRequestSignWithoutProtocolRejected(t *testing.T) {
	ctx := context.Background()
	coord, _, _, fixtures := newTestCoordinator(t)
	markOnline(t, coord.presence, fixtures["p1"].pub, "p1")
	markOnline(t, coord.presence, fixtures["p2"].pub, "p2")

	req := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID: "client-supplied",
			Protocol:  sdkprotocol.ProtocolTypeUnspecified,
			Operation: sdkprotocol.OperationTypeSign,
			Threshold: 1,
			Participants: []*sdkprotocol.SessionParticipant{
				{ParticipantID: "p1", PartyKey: []byte("p1"), IdentityPublicKey: fixtures["p1"].pub},
				{ParticipantID: "p2", PartyKey: []byte("p2"), IdentityPublicKey: fixtures["p2"].pub},
			},
			Sign: &sdkprotocol.SignPayload{
				KeyID:        "wallet-1",
				SigningInput: []byte("message"),
			},
		},
	}

	rawReply, err := coord.HandleRequest(ctx, OperationSign, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var rejected sdkprotocol.RequestRejected
	if err := json.Unmarshal(rawReply, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Accepted {
		t.Fatalf("expected sign request without protocol to be rejected")
	}
	if rejected.ErrorCode != ErrorCodeValidation {
		t.Fatalf("error code = %s, want %s", rejected.ErrorCode, ErrorCodeValidation)
	}
}

func TestNewCoordinator_AppliesDefaultNowAndTickDoesNotPanic(t *testing.T) {
	store, err := NewMemorySessionStore(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	coord, err := NewCoordinator(CoordinatorConfig{
		CoordinatorID:     "coordinator-1",
		Signer:            fakeSigner{},
		Store:             store,
		Presence:          NewInMemoryPresenceView(),
		Controls:          &fakeControlPublisher{},
		Results:           &fakeResultPublisher{},
		DefaultSessionTTL: 120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if coord.now == nil {
		t.Fatalf("expected default now function")
	}
	if _, err := coord.Tick(context.Background()); err != nil {
		t.Fatalf("tick returned error: %v", err)
	}
}

func TestNewCoordinator_RejectsInvalidConfig(t *testing.T) {
	store, err := NewMemorySessionStore(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCoordinator(CoordinatorConfig{
		CoordinatorID: "coordinator-1",
		Store:         store,
		Presence:      NewInMemoryPresenceView(),
		Controls:      &fakeControlPublisher{},
		Results:       &fakeResultPublisher{},
	})
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

type participantKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestCoordinator(t *testing.T) (*Coordinator, *fakeControlPublisher, *fakeResultPublisher, map[string]participantKey) {
	t.Helper()
	fixtures := map[string]participantKey{}
	for _, id := range []string{"p1", "p2"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[id] = participantKey{pub: pub, priv: priv}
	}

	store, err := NewMemorySessionStore(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	controls := &fakeControlPublisher{}
	results := &fakeResultPublisher{}
	coord, err := NewCoordinator(CoordinatorConfig{
		CoordinatorID:     "coordinator-1",
		Signer:            fakeSigner{},
		EventVerifier:     Ed25519SessionEventVerifier{},
		Store:             store,
		KeyInfoStore:      NewMemoryKeyInfoStore(),
		Presence:          NewInMemoryPresenceView(),
		Controls:          controls,
		Results:           results,
		DefaultSessionTTL: 120 * time.Second,
		Now:               func() time.Time { return time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return coord, controls, results, fixtures
}

func newSessionStart(keys map[string]participantKey) *sdkprotocol.SessionStart {
	return &sdkprotocol.SessionStart{
		SessionID: "client-supplied",
		Protocol:  sdkprotocol.ProtocolTypeECDSA,
		Operation: sdkprotocol.OperationTypeSign,
		Threshold: 1,
		Participants: []*sdkprotocol.SessionParticipant{
			{ParticipantID: "p1", PartyKey: []byte("p1"), IdentityPublicKey: keys["p1"].pub},
			{ParticipantID: "p2", PartyKey: []byte("p2"), IdentityPublicKey: keys["p2"].pub},
		},
		Sign: &sdkprotocol.SignPayload{
			KeyID:        "k",
			SigningInput: []byte("message"),
		},
	}
}

func emitSignedEvent(t *testing.T, coord *Coordinator, sessionID string, keys map[string]participantKey, participant string, body *sdkprotocol.SessionEvent) {
	t.Helper()
	event := &sdkprotocol.SessionEvent{
		SessionID:     sessionID,
		ParticipantID: participant,
		Sequence:      uint64(time.Now().UnixNano()),
	}
	event.PeerJoined = body.PeerJoined
	event.PeerReady = body.PeerReady
	event.PeerKeyExchangeDone = body.PeerKeyExchangeDone
	event.SessionCompleted = body.SessionCompleted
	event.SessionFailed = body.SessionFailed
	payload, err := sdkprotocol.SessionEventSigningBytes(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Signature = ed25519.Sign(keys[participant].priv, payload)
	if err := coord.HandleSessionEvent(context.Background(), mustJSON(t, event)); err != nil {
		t.Fatal(err)
	}
}

func markOnline(t *testing.T, presence PresenceView, _ ed25519.PublicKey, participantID string) {
	t.Helper()
	err := presence.ApplyPresence(sdkprotocol.PresenceEvent{
		PeerID:         participantID,
		Status:         sdkprotocol.PresenceStatusOnline,
		Transport:      sdkprotocol.TransportTypeNATS,
		ConnectionID:   "conn-" + participantID,
		LastSeenUnixMs: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
