package types

import "encoding/json"

// Message represents a protocol message
type TaurusMessage struct {
	SID         string
	From        string
	To          []string
	IsBroadcast bool
	Data        []byte
	Signature   []byte
}

func (m *TaurusMessage) MarshalForSigning() ([]byte, error) {
	// Exclude the Signature field from the signed payload to ensure deterministic signatures
	type signPayload struct {
		SID         string   `json:"sid"`
		From        string   `json:"from"`
		To          []string `json:"to"`
		IsBroadcast bool     `json:"isBroadcast"`
		Data        []byte   `json:"data"`
	}
	sp := signPayload{
		SID:         m.SID,
		From:        m.From,
		To:          m.To,
		IsBroadcast: m.IsBroadcast,
		Data:        m.Data,
	}
	return json.Marshal(sp)
}

// KeyData represents the result of key generation
type KeyData struct {
	SID         string
	Type        string
	Payload     []byte
	PubKeyBytes []byte
}
