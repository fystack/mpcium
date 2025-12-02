package ckdutil

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

const (
	hardenedKeyStart = 0x80000000
	// Compressed pubkey: 1-byte prefix (02/03) + 32-byte X coordinate.
	pubKeyBytesLenCompressed = 33
	// BIP32 specifies child index serialized as 4-byte big-endian (ser32).
	childIndexBytes           = 4
	pubKeyCompressedEven byte = 0x2
	pubKeyCompressedOdd  byte = 0x3
)

// DeriveEd25519ChildCompressed derives a non-hardened child public key on ed25519 and returns the 32-byte compressed key.
func DeriveEd25519ChildCompressed(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) == 0 {
		return nil, fmt.Errorf("master public key is empty")
	}

	pubKey, err := edwards.ParsePubKey(masterPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode master pubkey: %w", err)
	}

	return deriveEd25519ChildCompressed(pubKey, chainCodeHex, path)
}

// DeriveSecp256k1ChildCompressed derives a non-hardened child public key on secp256k1 and returns the 33-byte compressed key.
func DeriveSecp256k1ChildCompressed(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) != 33 {
		return nil, fmt.Errorf("invalid master pubkey length: %d", len(masterPubKey))
	}

	curve := btcec.S256()
	pubKey, err := btcec.ParsePubKey(masterPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode master pubkey: %w", err)
	}

	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("decode chain code: %w", err)
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("invalid chain code length: %d", len(chainCode))
	}

	currentX := new(big.Int).Set(pubKey.X())
	currentY := new(big.Int).Set(pubKey.Y())
	currentChainCode := append([]byte(nil), chainCode...)

	for _, index := range path {
		if index >= hardenedKeyStart {
			return nil, fmt.Errorf("hardened derivation not supported: %d", index)
		}

		data := make([]byte, pubKeyBytesLenCompressed+childIndexBytes)
		copy(data, serializeCompressed(currentX, currentY))
		binary.BigEndian.PutUint32(data[pubKeyBytesLenCompressed:], index)

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(data)
		ilr := mac.Sum(nil)
		il := ilr[:32]
		ir := ilr[32:]

		ilNum := new(big.Int).SetBytes(il)
		if ilNum.Sign() == 0 || ilNum.Cmp(curve.Params().N) >= 0 {
			return nil, fmt.Errorf("invalid IL for index %d", index)
		}

		deltaX, deltaY := curve.ScalarBaseMult(ilNum.Bytes())
		childX, childY := curve.Add(currentX, currentY, deltaX, deltaY)
		if childX == nil || childY == nil || childX.Sign() == 0 || childY.Sign() == 0 {
			return nil, fmt.Errorf("invalid child point at index %d", index)
		}

		currentX, currentY = childX, childY
		currentChainCode = ir
	}

	return serializeCompressed(currentX, currentY), nil
}

// --- shared helpers (non-hardened) ---

func deriveEd25519ChildCompressed(masterPub *edwards.PublicKey, chainCodeHex string, path []uint32) ([]byte, error) {
	if masterPub == nil || masterPub.X == nil || masterPub.Y == nil {
		return nil, fmt.Errorf("invalid master public key")
	}

	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("decode chain code: %w", err)
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("invalid chain code length: %d", len(chainCode))
	}

	curve := edwards.Edwards()
	currentX := new(big.Int).Set(masterPub.X)
	currentY := new(big.Int).Set(masterPub.Y)
	currentChainCode := append([]byte(nil), chainCode...)

	for _, index := range path {
		if index >= hardenedKeyStart {
			return nil, fmt.Errorf("hardened derivation not supported: %d", index)
		}

		data := make([]byte, pubKeyBytesLenCompressed+childIndexBytes)
		copy(data, serializeCompressed(currentX, currentY))
		binary.BigEndian.PutUint32(data[pubKeyBytesLenCompressed:], index)

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(data)
		ilr := mac.Sum(nil)
		il := ilr[:32]
		ir := ilr[32:]

		ilNum := new(big.Int).SetBytes(il)
		ilNum.Mod(ilNum, curve.Params().N)
		if ilNum.Sign() == 0 || ilNum.Cmp(curve.Params().N) >= 0 {
			return nil, fmt.Errorf("invalid IL for index %d", index)
		}

		deltaX, deltaY := curve.ScalarBaseMult(ilNum.Bytes())
		childX, childY := curve.Add(currentX, currentY, deltaX, deltaY)
		if childX == nil || childY == nil || childX.Sign() == 0 || childY.Sign() == 0 {
			return nil, fmt.Errorf("invalid child point at index %d", index)
		}

		currentX, currentY = childX, childY
		currentChainCode = ir
	}

	childPub := edwards.PublicKey{
		Curve: curve,
		X:     currentX,
		Y:     currentY,
	}

	return childPub.SerializeCompressed(), nil
}

// serializeCompressed matches the node compression (33 bytes).
func serializeCompressed(x, y *big.Int) []byte {
	b := make([]byte, 0, pubKeyBytesLenCompressed)
	format := pubKeyCompressedEven
	if isOdd(y) {
		format = pubKeyCompressedOdd
	}
	b = append(b, format)
	return paddedAppend(b, 32, x.Bytes())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}
