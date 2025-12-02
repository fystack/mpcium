package ckdutil

import (
	"encoding/hex"
	"testing"

	tsscrypto "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/stretchr/testify/require"
)

func TestEd25519StandaloneMatchesTSS(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i + 1)
	}
	chainCodeHex := hex.EncodeToString(chainCode)

	curve := edwards.Edwards()
	masterPub := edwards.PublicKey{
		Curve: curve,
		X:     curve.Params().Gx,
		Y:     curve.Params().Gy,
	}
	masterPubBytes := masterPub.SerializeCompressed()

	masterPoint, err := tsscrypto.NewECPoint(curve, masterPub.X, masterPub.Y)
	require.NoError(t, err)

	ckd, err := mpc.NewCKDFromHex(chainCodeHex)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		path := []uint32{44, 501, uint32(i), 0}

		localChild, err := DeriveEd25519ChildCompressed(masterPubBytes, chainCodeHex, path)
		require.NoErrorf(t, err, "local derivation failed at index %d", i)

		_, tssChild, err := ckd.Derive("wallet-ed25519-test", masterPoint, path, tss.Edwards())
		require.NoErrorf(t, err, "tss derivation failed at index %d", i)

		tssPub := edwards.PublicKey{Curve: curve, X: tssChild.PublicKey.X(), Y: tssChild.PublicKey.Y()}
		require.Equalf(t, tssPub.SerializeCompressed(), localChild, "pubkey mismatch at index %d", i)
	}
}

func TestSecp256k1StandaloneMatchesTSS(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(0xaa - i)
	}
	chainCodeHex := hex.EncodeToString(chainCode)

	curve := btcec.S256()
	masterX, masterY := curve.Params().Gx, curve.Params().Gy
	masterPubBytes := serializeCompressed(masterX, masterY)

	masterPoint, err := tsscrypto.NewECPoint(curve, masterX, masterY)
	require.NoError(t, err)

	ckd, err := mpc.NewCKDFromHex(chainCodeHex)
	require.NoError(t, err)

	for i := 0; i < 1000; i++ {
		path := []uint32{44, 60, 0, 0, uint32(i)}

		localChild, err := DeriveSecp256k1ChildCompressed(masterPubBytes, chainCodeHex, path)
		require.NoErrorf(t, err, "local derivation failed at index %d", i)

		_, tssChild, err := ckd.Derive("wallet-secp-test", masterPoint, path, tss.S256())
		require.NoErrorf(t, err, "tss derivation failed at index %d", i)

		tssChildBytes := serializeCompressed(tssChild.PublicKey.X(), tssChild.PublicKey.Y())
		require.Equalf(t, tssChildBytes, localChild, "pubkey mismatch at index %d", i)
	}
}
