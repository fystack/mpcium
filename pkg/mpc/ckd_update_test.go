package mpc

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/crypto"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/stretchr/testify/require"
)

// These tests lock the behaviour of the CKD "update public key + adjust BigXj"
// helpers after the tss-lib v2 -> v3 migration, where ckd.ExtendedKey.PublicKey
// changed from *crypto.ECPoint to ecdsa.PublicKey and the helpers now accept an
// ecdsa.PublicKey child key. They verify the two invariants signing relies on:
//   1. the wallet public key is replaced by the derived child public key, and
//   2. every BigXj share point is shifted by delta*G,
// so a signature produced with the adjusted shares verifies against the child key.

func TestECDSAUpdateSinglePublicKeyAndAdjustBigXj(t *testing.T) {
	ec := tss.S256()
	c := &CKD{}

	// Arbitrary starting share points: BigXj = [G, 2G].
	bigX0 := crypto.ScalarBaseMult(ec, big.NewInt(1))
	bigX1 := crypto.ScalarBaseMult(ec, big.NewInt(2))
	key := &ecdsaKeygen.LocalPartySaveData{}
	key.BigXj = []*crypto.ECPoint{bigX0, bigX1}
	key.ECDSAPub = crypto.ScalarBaseMult(ec, big.NewInt(9))

	delta := big.NewInt(123456789)
	gDelta := crypto.ScalarBaseMult(ec, delta)

	// child public key expressed as ecdsa.PublicKey, mirroring ckd.ExtendedKey in v3.
	childPoint := crypto.ScalarBaseMult(ec, big.NewInt(777))
	childPk := ecdsa.PublicKey{Curve: ec, X: childPoint.X(), Y: childPoint.Y()}

	err := c.ECDSAUpdateSinglePublicKeyAndAdjustBigXj(delta, key, childPk, ec)
	require.NoError(t, err)

	require.True(t, key.ECDSAPub.Equals(childPoint), "ECDSAPub must equal the child key")

	wantX0, err := bigX0.Add(gDelta)
	require.NoError(t, err)
	wantX1, err := bigX1.Add(gDelta)
	require.NoError(t, err)
	require.True(t, key.BigXj[0].Equals(wantX0), "BigXj[0] must be shifted by delta*G")
	require.True(t, key.BigXj[1].Equals(wantX1), "BigXj[1] must be shifted by delta*G")
}

func TestEDDSAUpdateSinglePublicKeyAndAdjustBigXj(t *testing.T) {
	ec := tss.Edwards()
	c := &CKD{}

	bigX0 := crypto.ScalarBaseMult(ec, big.NewInt(3))
	bigX1 := crypto.ScalarBaseMult(ec, big.NewInt(5))
	key := &eddsaKeygen.LocalPartySaveData{}
	key.BigXj = []*crypto.ECPoint{bigX0, bigX1}
	key.EDDSAPub = crypto.ScalarBaseMult(ec, big.NewInt(11))

	delta := big.NewInt(424242)
	gDelta := crypto.ScalarBaseMult(ec, delta)

	childPoint := crypto.ScalarBaseMult(ec, big.NewInt(88))
	childPk := ecdsa.PublicKey{Curve: ec, X: childPoint.X(), Y: childPoint.Y()}

	err := c.EDDSAUpdateSinglePublicKeyAndAdjustBigXj(delta, key, childPk, ec)
	require.NoError(t, err)

	require.True(t, key.EDDSAPub.Equals(childPoint), "EDDSAPub must equal the child key")

	wantX0, err := bigX0.Add(gDelta)
	require.NoError(t, err)
	wantX1, err := bigX1.Add(gDelta)
	require.NoError(t, err)
	require.True(t, key.BigXj[0].Equals(wantX0), "BigXj[0] must be shifted by delta*G")
	require.True(t, key.BigXj[1].Equals(wantX1), "BigXj[1] must be shifted by delta*G")
}

// TestUpdateRejectsInvalidChildKey ensures a child key that is not on the curve
// is rejected rather than silently corrupting the stored share.
func TestUpdateRejectsInvalidChildKey(t *testing.T) {
	ec := tss.S256()
	c := &CKD{}
	key := &ecdsaKeygen.LocalPartySaveData{}
	key.BigXj = []*crypto.ECPoint{crypto.ScalarBaseMult(ec, big.NewInt(1))}
	key.ECDSAPub = crypto.ScalarBaseMult(ec, big.NewInt(1))

	// (2, 2) is not a point on secp256k1.
	bad := ecdsa.PublicKey{Curve: ec, X: big.NewInt(2), Y: big.NewInt(2)}
	err := c.ECDSAUpdateSinglePublicKeyAndAdjustBigXj(big.NewInt(1), key, bad, ec)
	require.Error(t, err)
}
