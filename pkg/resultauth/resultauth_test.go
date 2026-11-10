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

// The same vector is in apex pkg/wallet/mpc/resultauth, so a signing format change on either side fails there too.
func TestVector(t *testing.T) {
	const (
		seed      = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		publicKey = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
		nodeID    = "node-vector-0"
		subject   = "mpc.mpc_signing_result.complete"
		body      = `{"result_type":"success","wallet_id":"wallet-1","tx_id":"tx-1"}`
		signature = "IJjFJSE7bykp+PEfdzZ9SGC1tcd2fht4JjLMX1obph6gWR7tgNxo1PG1bfeotiaMpK/+a4VDUzDp907XvJa5AA=="
	)
	// Header names are part of the wire format: nats.Header.Get is case-sensitive.
	require.Equal(t, "Mpc-Node-Id", NodeIDHeader)
	require.Equal(t, "Mpc-Result-Sig", SignatureHeader)

	seedBytes, err := hex.DecodeString(seed)
	require.NoError(t, err)
	privateKey := ed25519.NewKeyFromSeed(seedBytes)
	require.Equal(t, publicKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)))

	headers, err := SignHeaders(keySigner{privateKey: privateKey}, nodeID, subject, []byte(body))
	require.NoError(t, err)
	require.Equal(t, signature, headers[SignatureHeader])

	lookup, err := NewKeyLookup(map[string]string{nodeID: publicKey})
	require.NoError(t, err)
	_, err = Verify(lookup, subject, []byte(body), headerOf(map[string]string{
		NodeIDHeader: nodeID, SignatureHeader: signature,
	}))
	require.NoError(t, err)
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
