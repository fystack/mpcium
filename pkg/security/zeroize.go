package security

import (
	ecdsakeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
)

// ZeroEcdsaKeygenLocalPartySaveData securely zeros out sensitive fields in an ECDSA LocalPartySaveData struct.
// It handles big.Ints and other sensitive data within the struct.
func ZeroEcdsaKeygenLocalPartySaveData(data *ecdsakeygen.LocalPartySaveData) {
	if data == nil {
		return
	}
	// Zero out the private key share and share ID.
	if data.Xi != nil {
		data.Xi.SetInt64(0)
	}
	if data.ShareID != nil {
		data.ShareID.SetInt64(0)
	}
}

// ZeroEddsaKeygenLocalPartySaveData securely zeros out sensitive fields in an EDDSA LocalPartySaveData struct.
func ZeroEddsaKeygenLocalPartySaveData(data *eddsakeygen.LocalPartySaveData) {
	if data == nil {
		return
	}
	if data.Xi != nil {
		data.Xi.SetInt64(0)
	}
	if data.ShareID != nil {
		data.ShareID.SetInt64(0)
	}
}

