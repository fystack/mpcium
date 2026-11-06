package client

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/types"
)

var ErrInvalidSigningResult = errors.New("signing result does not verify against the wallet public key")

// VerifySigningResult checks a successful signing result against the wallet public key, encoded as in
// KeygenResultEvent. For HD wallets pass the derived child public key. A forged result fails here
// without waiting for other nodes.
func VerifySigningResult(keyType types.KeyType, publicKey, tx []byte, result event.SigningResultEvent) error {
	if result.ResultType != event.ResultTypeSuccess {
		return fmt.Errorf("signing result is not a success: %s", result.ErrorCode)
	}
	// Nodes sign tx as a big integer, so leading zero bytes are not part of the signed message.
	message := new(big.Int).SetBytes(tx).Bytes()

	switch keyType {
	case types.KeyTypeSecp256k1:
		pub, err := encoding.DecodeECDSAPubKey(publicKey)
		if err != nil {
			return fmt.Errorf("invalid secp256k1 public key: %w", err)
		}
		if len(result.R) == 0 || len(result.S) == 0 {
			return ErrInvalidSigningResult
		}
		if !ecdsa.Verify(pub, message, new(big.Int).SetBytes(result.R), new(big.Int).SetBytes(result.S)) {
			return ErrInvalidSigningResult
		}
	case types.KeyTypeEd25519:
		pub, err := encoding.DecodeEDDSAPubKey(publicKey)
		if err != nil {
			return fmt.Errorf("invalid ed25519 public key: %w", err)
		}
		sig, err := edwards.ParseSignature(result.Signature)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSigningResult, err)
		}
		if !edwards.Verify(pub, message, sig.R, sig.S) {
			return ErrInvalidSigningResult
		}
	default:
		return fmt.Errorf("unsupported key type %q", keyType)
	}
	return nil
}
