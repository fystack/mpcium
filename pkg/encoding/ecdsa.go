package encoding

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

func EncodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key is nil")
	}

	params := pubKey.Curve.Params()
	expected := btcec.S256().Params()
	if params.P.Cmp(expected.P) != 0 || params.N.Cmp(expected.N) != 0 {
		return nil, errors.New("unsupported curve, expected secp256k1")
	}

	const coordSize = 32
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	if len(xBytes) > coordSize || len(yBytes) > coordSize {
		return nil, errors.New("coordinate length exceeds 32 bytes")
	}

	encoded := make([]byte, coordSize*2)
	copy(encoded[coordSize-len(xBytes):coordSize], xBytes)
	copy(encoded[coordSize*2-len(yBytes):], yBytes)

	return encoded, nil
}

func DecodeECDSAPubKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	if len(encodedKey) == 65 && encodedKey[0] == 0x04 {
		encodedKey = encodedKey[1:] // Strip uncompressed prefix
	}
	if len(encodedKey) != 64 {
		return nil, errors.New("invalid encoded key length, expected 64 bytes")
	}

	x := new(big.Int).SetBytes(encodedKey[:32])
	y := new(big.Int).SetBytes(encodedKey[32:])

	curve := btcec.S256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid public key: point not on secp256k1 curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
