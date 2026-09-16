package cosigner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	sdkstorage "github.com/fystack/mpcium-sdk/storage"
	"github.com/fystack/mpcium-sdk/participant"
)

type fakeRelay struct {
	published map[string][]byte
}

func (f *fakeRelay) Subscribe(string, func([]byte)) (Subscription, error) { return nil, nil }
func (f *fakeRelay) Publish(subject string, payload []byte) error {
	if f.published == nil {
		f.published = map[string][]byte{}
	}
	f.published[subject] = append([]byte(nil), payload...)
	return nil
}
func (f *fakeRelay) Flush() error                              { return nil }
func (f *fakeRelay) Close()                                    {}
func (f *fakeRelay) ProtocolType() sdkprotocol.TransportType   { return "" }

type fakeStores struct {
	share     []byte
	workspace string
}

func (s *fakeStores) LoadShare(sdkprotocol.ProtocolType, string) ([]byte, error) {
	return append([]byte(nil), s.share...), nil
}
func (s *fakeStores) SaveShare(sdkprotocol.ProtocolType, string, []byte) error { return nil }
func (s *fakeStores) LoadShareWorkspace(sdkprotocol.ProtocolType, string) (string, error) {
	return s.workspace, nil
}
func (s *fakeStores) SaveShareWorkspace(sdkprotocol.ProtocolType, string, string) error { return nil }
func (s *fakeStores) LoadPreparamsSlot(sdkprotocol.ProtocolType, string) ([]byte, error) {
	return nil, nil
}
func (s *fakeStores) SavePreparamsSlot(sdkprotocol.ProtocolType, string, []byte) error { return nil }
func (s *fakeStores) LoadActivePreparamsSlot(sdkprotocol.ProtocolType) (string, error) {
	return "", nil
}
func (s *fakeStores) SaveActivePreparamsSlot(sdkprotocol.ProtocolType, string) error { return nil }
func (s *fakeStores) StageShareRotation(sdkprotocol.ProtocolType, string, string, sdkstorage.ShareRotation) error {
	return nil
}
func (s *fakeStores) CommitShareRotation(sdkprotocol.ProtocolType, string, string) error { return nil }
func (s *fakeStores) AbortShareRotation(sdkprotocol.ProtocolType, string, string) error  { return nil }
func (s *fakeStores) LoadSessionCheckpoint(string) ([]byte, error)                       { return nil, nil }
func (s *fakeStores) SaveSessionCheckpoint(string, []byte) error                         { return nil }
func (s *fakeStores) DeleteSessionCheckpoint(string) error                               { return nil }
func (s *fakeStores) LoadSessionArtifacts(string) ([]byte, error)                        { return nil, nil }
func (s *fakeStores) SaveSessionArtifacts(string, []byte) error                          { return nil }
func (s *fakeStores) DeleteSessionArtifacts(string) error                                { return nil }
func (s *fakeStores) Close() error                                                       { return nil }

func newTestRuntime(t *testing.T, stores Stores, exportEnabled bool) (*Runtime, ed25519.PrivateKey, *fakeRelay) {
	t.Helper()
	orchPub, orchPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, nodePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := NewOrchestratorLookup("orch-1", orchPub)
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeRelay{}
	rt := &Runtime{
		cfg: Config{
			ParticipantID:      "node-1",
			OrchestratorID:     "orch-1",
			IdentityPrivateKey: nodePriv,
			ExportEnabled:      exportEnabled,
		},
		relay:              relay,
		stores:             stores,
		orchestratorLookup: lookup,
		sessions:           map[string]*participant.ParticipantSession{},
		sessionMeta:        map[string]sessionMeta{},
		pendingPeer:        nil,
	}
	return rt, orchPriv, relay
}

func signedExportControl(t *testing.T, orchPriv ed25519.PrivateKey, req *sdkprotocol.ExportShareRequest) *sdkprotocol.ControlMessage {
	t.Helper()
	msg := &sdkprotocol.ControlMessage{
		SessionID:      "export-1",
		OrchestratorID: "orch-1",
		ExportShare:    req,
	}
	payload, err := sdkprotocol.ControlSigningBytes(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature = ed25519.Sign(orchPriv, payload)
	return msg
}

func rsaRecipient(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), priv
}

func TestExportShareSuccess(t *testing.T) {
	share := []byte(`{"secret":"share-material"}`)
	stores := &fakeStores{share: share, workspace: "ws-1"}
	rt, orchPriv, relay := newTestRuntime(t, stores, true)
	pemBytes, rsaPriv := rsaRecipient(t)

	msg := signedExportControl(t, orchPriv, &sdkprotocol.ExportShareRequest{
		KeyID: "wallet-1", Protocol: sdkprotocol.ProtocolTypeECDSA, WorkspaceID: "ws-1", RecipientPubKeyPEM: pemBytes,
	})
	if err := rt.handleExportShare(msg); err != nil {
		t.Fatalf("handleExportShare: %v", err)
	}
	raw, ok := relay.published[sessionEventSubject("export-1")]
	if !ok {
		t.Fatal("no event published")
	}
	var ev sdkprotocol.SessionEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.ExportShareDone == nil {
		t.Fatal("expected ExportShareDone")
	}
	got, err := sdkprotocol.OpenExportEnvelope(ev.ExportShareDone.Envelope, rsaPriv)
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	if !bytes.Equal(got, share) {
		t.Fatalf("decrypted share mismatch: %s", got)
	}
}

func TestExportShareGateOff(t *testing.T) {
	stores := &fakeStores{share: []byte("x"), workspace: "ws-1"}
	rt, orchPriv, _ := newTestRuntime(t, stores, false)
	pemBytes, _ := rsaRecipient(t)
	msg := signedExportControl(t, orchPriv, &sdkprotocol.ExportShareRequest{
		KeyID: "w", Protocol: sdkprotocol.ProtocolTypeECDSA, WorkspaceID: "ws-1", RecipientPubKeyPEM: pemBytes,
	})
	if err := rt.handleExportShare(msg); err == nil {
		t.Fatal("expected export disabled error")
	}
}

func TestExportShareWorkspaceMismatch(t *testing.T) {
	stores := &fakeStores{share: []byte("x"), workspace: "ws-OTHER"}
	rt, orchPriv, _ := newTestRuntime(t, stores, true)
	pemBytes, _ := rsaRecipient(t)
	msg := signedExportControl(t, orchPriv, &sdkprotocol.ExportShareRequest{
		KeyID: "w", Protocol: sdkprotocol.ProtocolTypeECDSA, WorkspaceID: "ws-1", RecipientPubKeyPEM: pemBytes,
	})
	if err := rt.handleExportShare(msg); err == nil {
		t.Fatal("expected workspace mismatch error")
	}
}

func TestExportShareNoMetaLegacyAllowed(t *testing.T) {
	stores := &fakeStores{share: []byte("x"), workspace: ""}
	rt, orchPriv, relay := newTestRuntime(t, stores, true)
	pemBytes, _ := rsaRecipient(t)
	msg := signedExportControl(t, orchPriv, &sdkprotocol.ExportShareRequest{
		KeyID: "w", Protocol: sdkprotocol.ProtocolTypeECDSA, WorkspaceID: "ws-1", RecipientPubKeyPEM: pemBytes,
	})
	if err := rt.handleExportShare(msg); err != nil {
		t.Fatalf("legacy export (no meta) should be allowed via orchestrator authorization: %v", err)
	}
	if _, ok := relay.published[sessionEventSubject("export-1")]; !ok {
		t.Fatal("expected export event published for legacy share")
	}
}

func TestExportShareBadSignature(t *testing.T) {
	stores := &fakeStores{share: []byte("x"), workspace: "ws-1"}
	rt, _, _ := newTestRuntime(t, stores, true)
	pemBytes, _ := rsaRecipient(t)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	msg := signedExportControl(t, wrongPriv, &sdkprotocol.ExportShareRequest{
		KeyID: "w", Protocol: sdkprotocol.ProtocolTypeECDSA, WorkspaceID: "ws-1", RecipientPubKeyPEM: pemBytes,
	})
	if err := rt.handleExportShare(msg); err == nil {
		t.Fatal("expected signature verification failure")
	}
}
