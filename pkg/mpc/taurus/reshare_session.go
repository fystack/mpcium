package taurus

// ReshareSession represents a threshold signature resharing session
type ReshareSession interface {
	Session

	// Reshare starts the resharing protocol
	Reshare(done func())

	// GetPubKeyResult returns the public key after successful resharing
	GetPubKeyResult() []byte

	// IsNewPeer returns true if this node is joining as a new peer
	IsNewPeer() bool
}

// BaseReshareSession provides common functionality for reshare sessions
type BaseReshareSession struct {
	session
	isNewPeer    bool
	pubKeyResult []byte
}

// IsNewPeer returns true if this node is joining as a new peer
func (s *BaseReshareSession) IsNewPeer() bool {
	return s.isNewPeer
}

// GetPubKeyResult returns the public key after successful resharing
func (s *BaseReshareSession) GetPubKeyResult() []byte {
	return s.pubKeyResult
}
