package resultauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type keySigner struct{ privateKey ed25519.PrivateKey }

func (s keySigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(s.privateKey, data), nil }

func newTestNode(t *testing.T) (keySigner, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return keySigner{privateKey: privateKey}, hex.EncodeToString(publicKey)
}

func headerOf(headers map[string]string) func(string) string {
	return func(key string) string { return headers[key] }
}

func TestSignAndVerify(t *testing.T) {
	signer, publicKey := newTestNode(t)
	lookup, err := NewKeyLookup(map[string]string{"node0": publicKey})
	require.NoError(t, err)

	subject := "mpc.mpc_keygen_result.wallet-1"
	body := []byte(`{"wallet_id":"wallet-1"}`)
	headers, err := SignHeaders(signer, "node0", subject, body)
	require.NoError(t, err)

	nodeID, err := Verify(lookup, subject, body, headerOf(headers))
	require.NoError(t, err)
	require.Equal(t, "node0", nodeID)

	tests := []struct {
		name    string
		subject string
		body    []byte
		headers map[string]string
		wantErr error
	}{
		{"tampered body", subject, []byte(`{"wallet_id":"wallet-2"}`), headers, ErrInvalidSignature},
		{"replayed on another subject", "mpc.mpc_keygen_result.wallet-2", body, headers, ErrInvalidSignature},
		{"unsigned", subject, body, map[string]string{}, ErrUnsigned},
		{"unknown node", subject, body, map[string]string{NodeIDHeader: "node9", SignatureHeader: headers[SignatureHeader]}, ErrUnknownNode},
		{"malformed signature", subject, body, map[string]string{NodeIDHeader: "node0", SignatureHeader: "%%%"}, ErrInvalidSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(lookup, tt.subject, tt.body, headerOf(tt.headers))
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVerifyRejectsSignatureFromOtherNode(t *testing.T) {
	signer0, publicKey0 := newTestNode(t)
	_, publicKey1 := newTestNode(t)
	lookup, err := NewKeyLookup(map[string]string{"node0": publicKey0, "node1": publicKey1})
	require.NoError(t, err)

	subject, body := "mpc.mpc_signing_result.complete", []byte(`{"tx_id":"tx-1"}`)
	headers, err := SignHeaders(signer0, "node0", subject, body)
	require.NoError(t, err)
	headers[NodeIDHeader] = "node1"

	_, err = Verify(lookup, subject, body, headerOf(headers))
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	require.NoError(t, err)
	var vectors []struct {
		Seed      string `json:"seed"`
		PublicKey string `json:"public_key"`
		NodeID    string `json:"node_id"`
		Subject   string `json:"subject"`
		Body      string `json:"body"`
		Signature string `json:"signature"`
		// Header names are part of the wire format: nats.Header.Get is case-sensitive.
		NodeIDHeader    string `json:"node_id_header"`
		SignatureHeader string `json:"signature_header"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		require.Equal(t, v.NodeIDHeader, NodeIDHeader)
		require.Equal(t, v.SignatureHeader, SignatureHeader)
		seed, err := hex.DecodeString(v.Seed)
		require.NoError(t, err)
		privateKey := ed25519.NewKeyFromSeed(seed)
		require.Equal(t, v.PublicKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)))

		headers, err := SignHeaders(keySigner{privateKey: privateKey}, v.NodeID, v.Subject, []byte(v.Body))
		require.NoError(t, err)
		require.Equal(t, v.Signature, headers[SignatureHeader])

		lookup, err := NewKeyLookup(map[string]string{v.NodeID: v.PublicKey})
		require.NoError(t, err)
		_, err = Verify(lookup, v.Subject, []byte(v.Body), headerOf(map[string]string{
			NodeIDHeader: v.NodeID, SignatureHeader: v.Signature,
		}))
		require.NoError(t, err)
	}
}

func TestNewKeyLookupRejectsBadKeys(t *testing.T) {
	_, err := NewKeyLookup(map[string]string{"node0": "not-hex"})
	require.Error(t, err)
	_, err = NewKeyLookup(map[string]string{"node0": "abcd"})
	require.Error(t, err)
}

func TestLoadPublicKeys(t *testing.T) {
	dir := t.TempDir()
	_, publicKey0 := newTestNode(t)
	_, publicKey1 := newTestNode(t)
	writeIdentity := func(name, nodeID, publicKey string) {
		data, err := json.Marshal(map[string]string{"node_name": name, "node_id": nodeID, "public_key": publicKey})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+"_identity.json"), data, 0o600))
	}
	writeIdentity("node0", "id-0", publicKey0)
	writeIdentity("node1", "id-1", publicKey1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node0_private.key"), []byte("secret"), 0o600))

	publicKeys, err := LoadPublicKeys(dir)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"id-0": publicKey0, "id-1": publicKey1}, publicKeys)
}

type recordingQueue struct {
	messaging.MessageQueue
	topic   string
	message []byte
	options *messaging.EnqueueOptions
}

func (q *recordingQueue) Enqueue(topic string, message []byte, options *messaging.EnqueueOptions) error {
	q.topic, q.message, q.options = topic, message, options
	return nil
}

func TestSigningQueue(t *testing.T) {
	signer, publicKey := newTestNode(t)
	lookup, err := NewKeyLookup(map[string]string{"node0": publicKey})
	require.NoError(t, err)
	subject, body := "mpc.mpc_signing_result.complete", []byte(`{"tx_id":"tx-1"}`)

	inner := &recordingQueue{}
	queue := NewSigningQueue(inner, signer, "node0")
	require.NoError(t, queue.Enqueue(subject, body, &messaging.EnqueueOptions{IdempotententKey: "sign:tx-1"}))

	require.Equal(t, "sign:tx-1", inner.options.IdempotententKey)
	header := nats.Header{}
	for k, v := range inner.options.Headers {
		header.Set(k, v)
	}
	nodeID, err := Verify(lookup, inner.topic, inner.message, header.Get)
	require.NoError(t, err)
	require.Equal(t, "node0", nodeID)
}

func TestSigningQueueKeepsCallerHeaders(t *testing.T) {
	signer, _ := newTestNode(t)
	inner := &recordingQueue{}
	queue := NewSigningQueue(inner, signer, "node0")
	callerHeaders := map[string]string{"ClientID": "client-a"}

	require.NoError(t, queue.Enqueue("subject", []byte("body"), &messaging.EnqueueOptions{Headers: callerHeaders}))
	require.Equal(t, "client-a", inner.options.Headers["ClientID"])
	require.Len(t, callerHeaders, 1)
}

func TestLoadPublicKeysFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_public_keys.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"id-0": "aa", "id-1": "bb"}`), 0o600))

	publicKeys, err := LoadPublicKeysFile(path)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"id-0": "aa", "id-1": "bb"}, publicKeys)

	_, err = LoadPublicKeysFile(filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
