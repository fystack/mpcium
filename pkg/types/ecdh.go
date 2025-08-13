package types

import (
	"encoding/json"
	"time"
)

type ECDHMessage struct {
	From      string    `json:"from"`
	PublicKey []byte    `json:"public_key"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
}

// MarshalForSigning returns the deterministic JSON bytes for signing
func (msg *ECDHMessage) MarshalForSigning() ([]byte, error) {
	// Create a map with ordered keys
	signingData := map[string]interface{}{
		"from":      msg.From,
		"publicKey": msg.PublicKey,
		"timestamp": msg.Timestamp,
	}

	// Use json.Marshal with sorted keys
	return json.Marshal(signingData)
}
