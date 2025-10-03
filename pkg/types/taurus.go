package types

// Message represents a protocol message
type TaurusMessage struct {
	SessionID    string   `json:"session_id"`
	SenderID     string   `json:"sender_id"`
	RecipientIDs []string `json:"recipient_ids"`
	Body         []byte   `json:"body"`
	IsBroadcast  bool     `json:"is_broadcast"`
}

// KeyData represents the result of key generation
type KeyData struct {
	SID     string
	Type    string
	Payload []byte
}
