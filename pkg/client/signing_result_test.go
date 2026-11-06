package client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/stretchr/testify/require"
)

// The leading zero byte checks that verification matches how nodes turn tx into a big integer.
var testTx = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func TestVerifySigningResultSecp256k1(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub, err := encoding.EncodeS256PubKey(priv.PubKey().ToECDSA())
	require.NoError(t, err)
	r, s, err := ecdsa.Sign(rand.Reader, priv.ToECDSA(), testTx[1:])
	require.NoError(t, err)
	result := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, R: r.Bytes(), S: s.Bytes()}

	require.NoError(t, VerifySigningResult(types.KeyTypeSecp256k1, pub, testTx, result))

	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	otherPub, err := encoding.EncodeS256PubKey(other.PubKey().ToECDSA())
	require.NoError(t, err)
	require.ErrorIs(t, VerifySigningResult(types.KeyTypeSecp256k1, otherPub, testTx, result), ErrInvalidSigningResult)
	require.ErrorIs(t, VerifySigningResult(types.KeyTypeSecp256k1, pub, []byte("other tx"), result), ErrInvalidSigningResult)
}

func TestVerifySigningResultEd25519(t *testing.T) {
	priv, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)
	pub, err := encoding.EncodeEDDSAPubKey(priv.PubKey())
	require.NoError(t, err)
	sig, err := priv.Sign(testTx[1:])
	require.NoError(t, err)
	result := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, Signature: sig.Serialize()}

	require.NoError(t, VerifySigningResult(types.KeyTypeEd25519, pub, testTx, result))
	require.ErrorIs(t, VerifySigningResult(types.KeyTypeEd25519, pub, []byte("other tx"), result), ErrInvalidSigningResult)
}

func TestVerifySigningResultRejectsErrorResult(t *testing.T) {
	result := event.SigningResultEvent{ResultType: event.ResultTypeError, ErrorCode: event.ErrorCodeNotMajority}
	require.Error(t, VerifySigningResult(types.KeyTypeEd25519, nil, testTx, result))
}
