package coordinator

import (
	"context"
	"strings"
	"testing"

	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

func TestEd25519SessionEventVerifierRejectsInvalidPublicKeyLength(t *testing.T) {
	verifier := Ed25519SessionEventVerifier{}
	session := &Session{
		ParticipantKeys: map[string][]byte{
			"peer-1": make([]byte, 64),
		},
	}
	event := &sdkprotocol.SessionEvent{
		ParticipantID: "peer-1",
	}

	err := verifier.VerifySessionEvent(context.Background(), session, event)
	if err == nil {
		t.Fatal("expected error for invalid participant public key length")
	}
	if !strings.Contains(err.Error(), "invalid participant public key length") {
		t.Fatalf("unexpected error: %v", err)
	}
}
