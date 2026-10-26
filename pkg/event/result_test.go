package event

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type testSigner struct {
	nodeID string
	priv   ed25519.PrivateKey
}

func (s *testSigner) NodeID() string                   { return s.nodeID }
func (s *testSigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(s.priv, data), nil }

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &testSigner{nodeID: "node0", priv: priv}
}

func newTestLookup(t *testing.T, signer *testSigner) NodeKeyLookup {
	t.Helper()
	pub, ok := signer.priv.Public().(ed25519.PublicKey)
	require.True(t, ok)
	return func(nodeID string) ([]byte, error) {
		if nodeID != signer.nodeID {
			return nil, fmt.Errorf("unknown node: %s", nodeID)
		}
		return pub, nil
	}
}

func TestSignAndVerifyNodeResult(t *testing.T) {
	signer := newTestSigner(t)
	lookup := newTestLookup(t, signer)

	t.Run("signing result", func(t *testing.T) {
		e := SigningResultEvent{WalletID: "w1", TxID: "tx1", R: []byte{1}, S: []byte{2}}
		require.NoError(t, SignNodeResult(&e, signer))
		require.Equal(t, signer.nodeID, e.NodeID)
		require.NotEmpty(t, e.ResultSignature)

		require.NoError(t, VerifyNodeResult(e.NodeID, e.ResultSignature, &e, lookup))

		e.WalletID = "tampered"
		require.Error(t, VerifyNodeResult(e.NodeID, e.ResultSignature, &e, lookup))
	})

	t.Run("keygen result", func(t *testing.T) {
		e := KeygenResultEvent{WalletID: "w1", ECDSAPubKey: []byte{3}}
		require.NoError(t, SignNodeResult(&e, signer))
		require.NoError(t, VerifyNodeResult(e.NodeID, e.ResultSignature, &e, lookup))
	})

	t.Run("resharing result", func(t *testing.T) {
		e := ResharingResultEvent{WalletID: "w1", NewThreshold: 2}
		require.NoError(t, SignNodeResult(&e, signer))
		require.NoError(t, VerifyNodeResult(e.NodeID, e.ResultSignature, &e, lookup))
	})
}

func TestVerifyNodeResultRejects(t *testing.T) {
	signer := newTestSigner(t)
	lookup := newTestLookup(t, signer)

	t.Run("unsigned event", func(t *testing.T) {
		e := SigningResultEvent{WalletID: "w1"}
		require.Error(t, VerifyNodeResult(e.NodeID, e.ResultSignature, &e, lookup))
	})

	t.Run("unknown node", func(t *testing.T) {
		e := SigningResultEvent{WalletID: "w1"}
		require.NoError(t, SignNodeResult(&e, signer))
		require.Error(t, VerifyNodeResult("node9", e.ResultSignature, &e, lookup))
	})

	t.Run("nil lookup skips verification", func(t *testing.T) {
		e := SigningResultEvent{WalletID: "w1"}
		require.NoError(t, VerifyNodeResult("", nil, &e, nil))
	})
}
