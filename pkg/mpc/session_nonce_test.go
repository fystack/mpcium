package mpc

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestSessionNonceDeterministic is the property every node relies on: the same
// signed initiator payload must yield a byte-identical nonce, or SSID-bound
// proofs fail verification across the cluster.
func TestSessionNonceDeterministic(t *testing.T) {
	msg := &types.GenerateKeyMessage{WalletID: "wallet-abc", Signature: []byte("sig-a")}
	other := &types.GenerateKeyMessage{WalletID: "wallet-abc", Signature: []byte("different-sig")}

	n1, err := SessionNonceFromInitiator(NonceDomainKeygen, msg)
	require.NoError(t, err)
	n2, err := SessionNonceFromInitiator(NonceDomainKeygen, other)
	require.NoError(t, err)

	// Raw() excludes the signature, so nonce depends only on the signed payload.
	require.Equal(t, 0, n1.Cmp(n2), "same wallet ID must give the same nonce regardless of signature bytes")
	require.Positive(t, n1.Sign(), "nonce must be a positive integer")
}

func TestSessionNonceUniquePerWallet(t *testing.T) {
	a, err := SessionNonceFromInitiator(NonceDomainKeygen, &types.GenerateKeyMessage{WalletID: "wallet-a"})
	require.NoError(t, err)
	b, err := SessionNonceFromInitiator(NonceDomainKeygen, &types.GenerateKeyMessage{WalletID: "wallet-b"})
	require.NoError(t, err)
	require.NotEqual(t, 0, a.Cmp(b))
}

// TestSessionNonceDomainSeparation ensures a nonce derived for one ceremony type
// can never collide with another, even on structurally similar payloads.
func TestSessionNonceDomainSeparation(t *testing.T) {
	keygen, err := SessionNonceFromInitiator(NonceDomainKeygen, &types.GenerateKeyMessage{WalletID: "w"})
	require.NoError(t, err)
	reshare, err := SessionNonceFromInitiator(NonceDomainReshare, &types.ResharingMessage{WalletID: "w", SessionID: "s"})
	require.NoError(t, err)
	signing, err := SessionNonceFromInitiator(NonceDomainSigning, &types.SignTxMessage{WalletID: "w", TxID: "t"})
	require.NoError(t, err)

	require.NotEqual(t, 0, keygen.Cmp(reshare))
	require.NotEqual(t, 0, keygen.Cmp(signing))
	require.NotEqual(t, 0, reshare.Cmp(signing))
}

func TestSessionNonceReshareVariesWithSessionID(t *testing.T) {
	base := &types.ResharingMessage{WalletID: "w", SessionID: "s1", NodeIDs: []string{"n1", "n2"}, NewThreshold: 1}
	retry := &types.ResharingMessage{WalletID: "w", SessionID: "s2", NodeIDs: []string{"n1", "n2"}, NewThreshold: 1}

	n1, err := SessionNonceFromInitiator(NonceDomainReshare, base)
	require.NoError(t, err)
	n2, err := SessionNonceFromInitiator(NonceDomainReshare, retry)
	require.NoError(t, err)
	require.NotEqual(t, 0, n1.Cmp(n2), "a fresh session ID must produce a fresh nonce")
}

func TestNewTSSParametersRequiresNonce(t *testing.T) {
	ctx := tss.NewPeerContext([]*tss.PartyID{})
	_, err := newTSSParameters(tss.S256(), ctx, nil, 3, 2, nil)
	require.ErrorIs(t, err, ErrNilSessionNonce)

	_, err = newTSSReSharingParameters(tss.S256(), ctx, ctx, nil, 3, 2, 3, 2, nil)
	require.ErrorIs(t, err, ErrNilSessionNonce)
}

func TestNewTSSParametersSetsNonce(t *testing.T) {
	nonce := big.NewInt(0xC0FFEE)
	ctx := tss.NewPeerContext([]*tss.PartyID{})
	params, err := newTSSParameters(tss.S256(), ctx, nil, 3, 2, nonce)
	require.NoError(t, err)
	require.Equal(t, 0, params.SessionNonce().Cmp(nonce))
}
