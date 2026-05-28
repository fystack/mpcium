package cosigner

import (
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type Subscription interface {
	Unsubscribe() error
}

// Relay is the transport abstraction used by the cosigner runtime. NATS is
// the only implementation today; the interface stays so the runtime can be
// driven by an injected transport (e.g. mpcium's shared NATS connection) or
// a fake in tests.
type Relay interface {
	Subscribe(subject string, handler func([]byte)) (Subscription, error)
	Publish(subject string, payload []byte) error
	Flush() error
	Close()
	ProtocolType() sdkprotocol.TransportType
}

func NewRelayFromConfig(cfg Config) (Relay, error) {
	return NewNATSRelay(cfg.NATS)
}
