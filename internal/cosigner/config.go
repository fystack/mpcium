package cosigner

import "time"

type Config struct {
	NodeID               string
	NATSURL              string
	CoordinatorID        string
	CoordinatorPublicKey []byte
	IdentityPrivateKey   []byte
	DataDir              string
	MaxActiveSessions    int
	PresenceInterval     time.Duration
	TickInterval         time.Duration
}
