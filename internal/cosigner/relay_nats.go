package cosigner

import (
	"fmt"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type NATSRelay struct {
	nc *nats.Conn
}

func NewNATSRelay(url string) (Relay, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	return &NATSRelay{nc: nc}, nil
}

func (t *NATSRelay) Subscribe(subject string, handler func([]byte)) (Subscription, error) {
	logger.Info("relay nats subscribe", "subject", subject)
	return t.nc.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
}

func (t *NATSRelay) Publish(subject string, payload []byte) error {
	logger.Debug("relay nats publish", "subject", subject)
	return t.nc.Publish(subject, payload)
}

func (t *NATSRelay) Flush() error {
	return t.nc.Flush()
}

func (t *NATSRelay) Close() {
	t.nc.Close()
}

func (t *NATSRelay) ProtocolType() sdkprotocol.TransportType {
	return sdkprotocol.TransportTypeNATS
}
