package mpc

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/ckd"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/btcsuite/btcd/chaincfg"
)

const chainCodeLength = 32

var (
	ErrInvalidChainCode = errors.New("invalid chain code length")
	ErrNilKey           = errors.New("key cannot be nil")
	ErrNilPoint         = errors.New("point cannot be nil")
)

// CKD handles Child Key Derivation (ENV-based)
type CKD struct {
	masterChainCode []byte
}

// NewCKDFromHex creates CKD from a hex-encoded chain code string (32 bytes).
func NewCKDFromHex(hexStr string) (*CKD, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("chain code is empty")
	}
	code, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid chain code hex: %w", err)
	}
	if len(code) != chainCodeLength {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidChainCode, len(code), chainCodeLength)
	}
	return &CKD{masterChainCode: code}, nil
}

// GetMasterChainCode returns a copy of the chain code.
func (c *CKD) GetMasterChainCode() []byte {
	out := make([]byte, len(c.masterChainCode))
	copy(out, c.masterChainCode)
	return out
}

// Derive derives a child key from the master public key using the given path.
// Uses standard BIP32 derivation: same master key + same path = same child key.
// Each level in the path automatically gets its own chain code via HMAC(parent_chain_code, pubkey || index).
func (c *CKD) Derive(walletID string, masterPub *crypto.ECPoint, path []uint32, curve elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	if masterPub == nil {
		return nil, nil, ErrNilPoint
	}
	if curve == nil {
		return nil, nil, errors.New("curve cannot be nil")
	}

	masterCC := append([]byte(nil), c.masterChainCode...)

	return c.derivingPubkeyFromPath(masterPub, masterCC, path, curve)
}

// derivingPubkeyFromPath performs the actual derivation.
func (c *CKD) derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	net := &chaincfg.MainNetParams
	parent := &ckd.ExtendedKey{
		PublicKey:  masterPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	delta, extKey, err := ckd.DeriveChildKeyFromHierarchy(path, parent, ec.Params().N, ec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive child key: %w", err)
	}
	return delta, extKey, nil
}

// ECDSAUpdateSinglePublicKeyAndAdjustBigXj updates ECDSA public key and BigXj.
func (c *CKD) ECDSAUpdateSinglePublicKeyAndAdjustBigXj(delta *big.Int, key *ecdsaKeygen.LocalPartySaveData, childPk *crypto.ECPoint, ec elliptic.Curve) error {
	if key == nil {
		return ErrNilKey
	}
	if childPk == nil {
		return ErrNilPoint
	}
	gDelta := crypto.ScalarBaseMult(ec, delta)
	key.ECDSAPub = childPk
	for i := range key.BigXj {
		updated, err := key.BigXj[i].Add(gDelta)
		if err != nil {
			return fmt.Errorf("failed to update BigXj[%d]: %w", i, err)
		}
		key.BigXj[i] = updated
	}
	return nil
}

// EDDSAUpdateSinglePublicKeyAndAdjustBigXj updates EdDSA public key and BigXj.
func (c *CKD) EDDSAUpdateSinglePublicKeyAndAdjustBigXj(delta *big.Int, key *eddsaKeygen.LocalPartySaveData, childPk *crypto.ECPoint, ec elliptic.Curve) error {
	if key == nil {
		return ErrNilKey
	}
	if childPk == nil {
		return ErrNilPoint
	}
	gDelta := crypto.ScalarBaseMult(ec, delta)
	key.EDDSAPub = childPk
	for i := range key.BigXj {
		updated, err := key.BigXj[i].Add(gDelta)
		if err != nil {
			return fmt.Errorf("failed to update BigXj[%d]: %w", i, err)
		}
		key.BigXj[i] = updated
	}
	return nil
}
