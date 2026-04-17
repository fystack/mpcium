package cosigner

import (
	"fmt"

	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type Subscription interface {
	Unsubscribe() error
}

type Relay interface {
	Subscribe(subject string, handler func([]byte)) (Subscription, error)
	Publish(subject string, payload []byte) error
	Flush() error
	Close()
	ProtocolType() sdkprotocol.TransportType
}

func NewRelayFromConfig(cfg Config) (Relay, error) {
	switch cfg.RelayProvider {
	case RelayProviderNATS:
		return NewNATSRelay(cfg.NATS)
	case RelayProviderMQTT:
		return NewMQTTRelay(cfg.MQTT)
	default:
		return nil, fmt.Errorf("unsupported relay provider: %s", cfg.RelayProvider)
	}
}
