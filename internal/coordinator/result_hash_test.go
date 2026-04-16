package coordinator

import (
	"bytes"
	"testing"

	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

func TestCanonicalOperationResultHashIgnoresKeygenShareBlob(t *testing.T) {
	resultA := &sdkprotocol.Result{
		KeyShare: &sdkprotocol.KeyShareResult{
			KeyID:     "wallet-1",
			PublicKey: []byte{1, 2, 3},
			ShareBlob: []byte{9, 9, 9},
		},
	}
	resultB := &sdkprotocol.Result{
		KeyShare: &sdkprotocol.KeyShareResult{
			KeyID:     "wallet-1",
			PublicKey: []byte{1, 2, 3},
			ShareBlob: []byte{8, 8, 8},
		},
	}

	hashA := canonicalOperationResultHash(OperationKeygen, resultA)
	hashB := canonicalOperationResultHash(OperationKeygen, resultB)
	if hashA == "" || hashB == "" {
		t.Fatal("expected non-empty hashes")
	}
	if hashA != hashB {
		t.Fatalf("expected equal hashes for keygen results with different share blobs, got %q != %q", hashA, hashB)
	}
}

func TestCanonicalOperationResultHashUsesFullSignaturePayload(t *testing.T) {
	resultA := &sdkprotocol.Result{
		Signature: &sdkprotocol.SignatureResult{
			KeyID:     "wallet-1",
			Signature: []byte{1, 2, 3},
		},
	}
	resultB := &sdkprotocol.Result{
		Signature: &sdkprotocol.SignatureResult{
			KeyID:     "wallet-1",
			Signature: []byte{1, 2, 4},
		},
	}

	hashA := canonicalOperationResultHash(OperationSign, resultA)
	hashB := canonicalOperationResultHash(OperationSign, resultB)
	if hashA == hashB {
		t.Fatalf("expected different hashes for different signature payloads")
	}

	// Guard against accidental normalization that removes signature bytes.
	if bytes.Equal(resultA.Signature.Signature, resultB.Signature.Signature) {
		t.Fatal("invalid test setup")
	}
}
