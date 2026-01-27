package security

import (
	"math/big"

	ecdsakeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
)

// ZeroEcdsaKeygenLocalPartySaveData securely zeros out sensitive fields in an ECDSA LocalPartySaveData struct.
// It handles big.Ints and other sensitive data within the struct.
func ZeroEcdsaKeygenLocalPartySaveData(data *ecdsakeygen.LocalPartySaveData) {
	if data == nil {
		return
	}
	if data.Xi != nil {
		zeroBigInt(data.Xi)
	}
	if data.ShareID != nil {
		zeroBigInt(data.ShareID)
	}
}

// ZeroEddsaKeygenLocalPartySaveData securely zeros out sensitive fields in an EDDSA LocalPartySaveData struct.
func ZeroEddsaKeygenLocalPartySaveData(data *eddsakeygen.LocalPartySaveData) {
	if data == nil {
		return
	}
	if data.Xi != nil {
		zeroBigInt(data.Xi)
	}
	if data.ShareID != nil {
		zeroBigInt(data.ShareID)
	}
}

func zeroBigInt(x *big.Int) {
	if x == nil {
		return
	}
	words := x.Bits()
	for i := range words {
		words[i] = 0
	}
	x.SetInt64(0)
}
func ZeroBigIntForensic(x *big.Int) {
	zeroBigInt(x)
}

