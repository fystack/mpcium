package protocol

import (
	"crypto/ecdsa"
	"math/big"
)

// Message represents a protocol message
type Message interface {
	// GetFrom returns the sender ID
	GetFrom() string
	// GetTo returns the recipient IDs (nil for broadcast)
	GetTo() []string
	// GetData returns the message data
	GetData() []byte
	// IsBroadcast returns true if this is a broadcast message
	IsBroadcast() bool
}

// Party represents a participant in the protocol
type Party interface {
	// Update processes an incoming message
	Update(msg Message) error
	// Messages returns a channel of outgoing messages
	Messages() <-chan Message
	// Errors returns a channel of errors
	Errors() <-chan error
	// Done returns true when the protocol is complete
	Done() bool
	// Result returns the protocol result
	Result() (interface{}, error)
}

// KeyGenConfig represents the result of key generation
type KeyGenConfig interface {
	// GetPartyID returns this party's ID
	GetPartyID() string
	// GetThreshold returns the threshold value
	GetThreshold() int
	// GetPublicKey returns the group's public key
	GetPublicKey() *ecdsa.PublicKey
	// GetShare returns this party's secret share
	GetShare() *big.Int
	// GetSharePublicKey returns this party's public share
	GetSharePublicKey() *ecdsa.PublicKey
	// GetPartyIDs returns all party IDs
	GetPartyIDs() []string
	// Serialize returns the config as bytes
	Serialize() ([]byte, error)
}

// Signature represents a signature
type Signature interface {
	// GetR returns the R component
	GetR() *big.Int
	// GetS returns the S component
	GetS() *big.Int
	// Verify verifies the signature
	Verify(pubKey *ecdsa.PublicKey, message []byte) bool
	// Serialize returns the signature as bytes
	Serialize() ([]byte, error)
}

// PreSignature represents a preprocessed signature
type PreSignature interface {
	// GetID returns the presignature ID
	GetID() string
	// Validate validates the presignature
	Validate() error
}

// Protocol represents a threshold signature protocol implementation
type Protocol interface {
	// KeyGen starts a distributed key generation
	KeyGen(selfID string, partyIDs []string, threshold int) (Party, error)

	// Refresh refreshes shares from an existing config
	Refresh(config KeyGenConfig) (Party, error)

	// Sign starts a signing protocol
	Sign(config KeyGenConfig, signers []string, messageHash []byte) (Party, error)

	// PreSign starts a presigning protocol
	PreSign(config KeyGenConfig, signers []string) (Party, error)

	// PreSignOnline completes a signature with a presignature
	PreSignOnline(config KeyGenConfig, preSignature PreSignature, messageHash []byte) (Party, error)

	// Name returns the protocol name (e.g., "GG20", "CGGMP21")
	Name() string
}
