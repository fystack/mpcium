package ckdutil

import (
	"encoding/hex"
	"testing"

	tsscrypto "github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/stretchr/testify/require"
)

// goldenChainCode is a fixed chain code used to make the derivation outputs below
// fully deterministic and independent of any wallet state.
const goldenChainCode = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// TestCKDGoldenVectors pins the exact compressed child public keys produced by
// mpc.CKD.Derive for a fixed master key (curve generator G), chain code and set
// of BIP32 paths.
//
// Why this test exists:
// Child wallet addresses are derived deterministically from the master public
// key + chain code via tss-lib's CKD. A change in the tss-lib CKD algorithm
// (for example the modulo-N reduction of IL that was introduced in the v2->v3
// bump for Edwards curves) silently changes every derived address, which would
// make funds sent to previously-advertised addresses unspendable. These golden
// vectors were captured against github.com/fystack/tss-lib/v3 v3.0.1. If a
// future dependency bump changes any value here, this test MUST fail so the
// address-compatibility impact is reviewed explicitly rather than shipped
// silently.
func TestCKDGoldenVectors(t *testing.T) {
	ckd, err := mpc.NewCKDFromHex(goldenChainCode)
	require.NoError(t, err)

	t.Run("secp256k1", func(t *testing.T) {
		s := btcec.S256()
		master, err := tsscrypto.NewECPoint(s, s.Params().Gx, s.Params().Gy)
		require.NoError(t, err)

		cases := map[string][]uint32{
			"0250390820cfe4ddbba5f230b99288b194177e928896802d5b3a745339ed55805f": {44, 60, 0, 0, 0},
			"02c8c491ebdaa1b7576cc3b72c457dad089e954a45f0e2d1b4006600cd72085194": {44, 60, 0, 0, 7},
		}
		for want, path := range cases {
			_, ek, err := ckd.Derive("golden-secp", master, path, tss.S256())
			require.NoErrorf(t, err, "derive path %v", path)
			got := hex.EncodeToString(serializeCompressed(ek.PublicKey.X, ek.PublicKey.Y))
			require.Equalf(t, want, got, "secp256k1 child pubkey drift at path %v", path)
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		e := edwards.Edwards()
		master, err := tsscrypto.NewECPoint(e, e.Params().Gx, e.Params().Gy)
		require.NoError(t, err)

		cases := map[string][]uint32{
			"cf7d5569333be69b5488e36dd2ee07cd7f4b068a287638d02a1958cd64011a64": {44, 501, 0, 0},
			"1b36b2acad34ac48134cd6f1fce6e1e9be975e6f33dfc39888aaee23e4918d6c": {44, 501, 7, 0},
		}
		for want, path := range cases {
			_, ek, err := ckd.Derive("golden-eddsa", master, path, tss.Edwards())
			require.NoErrorf(t, err, "derive path %v", path)
			pk := edwards.PublicKey{Curve: e, X: ek.PublicKey.X, Y: ek.PublicKey.Y}
			got := hex.EncodeToString(pk.SerializeCompressed())
			require.Equalf(t, want, got, "ed25519 child pubkey drift at path %v", path)
		}
	})
}
