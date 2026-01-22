package security

import (
	"math/big"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
)
func TestZeroBigInt_OverwritesBackingWords(t *testing.T) {
	x := new(big.Int).Lsh(big.NewInt(1), 2048)
	wordsBefore := append([]big.Word(nil), x.Bits()...)
	if len(wordsBefore) == 0 {
		t.Fatal("expected non-empty big.Int words")
	}

	zeroBigInt(x)

	for i, w := range wordsBefore {
		if w == 0 {
			continue
		}
		if i < len(x.Bits()) && x.Bits()[i] != 0 {
			t.Fatalf("expected big.Int word %d to be overwritten", i)
		}
	}

	if x.Sign() != 0 {
		t.Fatalf("expected big.Int value to be zero, got %v", x)
	}
}

func TestZeroEcdsaKeygenLocalPartySaveData_Nil(t *testing.T) {
	ZeroEcdsaKeygenLocalPartySaveData(nil)
}

func TestZeroEcdsaKeygenLocalPartySaveData_ZeroesFields(t *testing.T) {
	data := &ecdsakeygen.LocalPartySaveData{}
	data.Xi = big.NewInt(123)
	data.ShareID = big.NewInt(456)

	ZeroEcdsaKeygenLocalPartySaveData(data)

	if data.Xi == nil || data.Xi.Sign() != 0 {
		t.Fatalf("expected Xi to be zero, got %v", data.Xi)
	}
	if data.ShareID == nil || data.ShareID.Sign() != 0 {
		t.Fatalf("expected ShareID to be zero, got %v", data.ShareID)
	}
}

func TestZeroEddsaKeygenLocalPartySaveData_Nil(t *testing.T) {
	ZeroEddsaKeygenLocalPartySaveData(nil)
}

func TestZeroEddsaKeygenLocalPartySaveData_ZeroesFields(t *testing.T) {
	data := &eddsakeygen.LocalPartySaveData{}
	data.Xi = big.NewInt(789)
	data.ShareID = big.NewInt(101112)

	ZeroEddsaKeygenLocalPartySaveData(data)

	if data.Xi == nil || data.Xi.Sign() != 0 {
		t.Fatalf("expected Xi to be zero, got %v", data.Xi)
	}
	if data.ShareID == nil || data.ShareID.Sign() != 0 {
		t.Fatalf("expected ShareID to be zero, got %v", data.ShareID)
	}
}