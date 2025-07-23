package mpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"

	"github.com/btcsuite/btcd/chaincfg"
)

// Child Key Derivation
type CKD struct {
	Store     infra.ConsulKV
	ChainCode []byte
	Path      []uint32
}

func NewCKD() *CKD {
	ckd := &CKD{
		Store: infra.GetConsulClient("development").KV(),
	}
	err := ckd.initializeChainCode()
	if err != nil {
		logger.Fatal("Failed to initialize chain code", err)
	}
	return ckd
}

func (c *CKD) UpdateSinglePublicKeyAndAdjustBigXj(
	keyDerivationDelta *big.Int,
	key *keygen.LocalPartySaveData,
	extendedChildPk *ecdsa.PublicKey,
	ec elliptic.Curve,
) error {
	var err error

	// Compute g^delta
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)

	// Update the public key
	key.ECDSAPub, err = crypto.NewECPoint(ec, extendedChildPk.X, extendedChildPk.Y)
	if err != nil {
		common.Logger.Errorf("error creating new extended child public key")
		return err
	}

	// Update each BigXj[i] := BigXj[i] + g^delta
	for j := range key.BigXj {
		key.BigXj[j], err = key.BigXj[j].Add(gDelta)
		if err != nil {
			common.Logger.Errorf("error in delta operation")
			return err
		}
	}

	return nil
}

func (c *CKD) Derive(masterPub *crypto.ECPoint, path []uint32, curve elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	return c.derivingPubkeyFromPath(masterPub, c.ChainCode, path, curve)
}

func (c *CKD) derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     masterPub.X(),
		Y:     masterPub.Y(),
	}

	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, ec.Params().N, ec)
}

func (c *CKD) initializeChainCode() error {
	logger.Info("Initializing chain code")

	// Try to get chain code from store
	val, _, err := c.Store.Get("chain_code", nil)
	if err == nil && val != nil && len(val.Value) == 32 {
		// Found existing chain code
		c.ChainCode = make([]byte, 32)
		copy(c.ChainCode, val.Value)
		logger.Info("Loaded existing chain code", "chainCode", c.ChainCode)
		return nil
	}

	// Not found or invalid: generate new chain code
	chainCode := make([]byte, 32)
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	max.Sub(max, big.NewInt(1))
	fillBytes(common.GetRandomPositiveInt(rand.Reader, max), chainCode)

	// Save to store
	_, err = c.Store.Put(&api.KVPair{Key: "chain_code", Value: chainCode}, nil)
	if err != nil {
		return fmt.Errorf("failed to store chain code: %w", err)
	}

	// Assign to CKD struct
	c.ChainCode = make([]byte, 32)
	copy(c.ChainCode, chainCode)
	logger.Info("Generated new chain code", "chainCode", c.ChainCode)
	return nil
}

func fillBytes(x *big.Int, buf []byte) []byte {
	b := x.Bytes()
	if len(b) > len(buf) {
		panic("buffer too small")
	}
	offset := len(buf) - len(b)
	for i := range buf {
		if i < offset {
			buf[i] = 0
		} else {
			buf[i] = b[i-offset]
		}
	}
	return buf
}
