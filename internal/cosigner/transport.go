package cosigner

import (
	"fmt"

	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type Subscription interface {
	Unsubscribe() error
}

type Transport interface {
	Subscribe(subject string, handler func([]byte)) (Subscription, error)
	Publish(subject string, payload []byte) error
	Flush() error
	Close()
	ProtocolType() sdkprotocol.TransportType
}

type natsTransport struct {
	nc *nats.Conn
}

func NewNATSTransport(url string) (Transport, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	return &natsTransport{nc: nc}, nil
}

func (t *natsTransport) Subscribe(subject string, handler func([]byte)) (Subscription, error) {
	return t.nc.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
}

func (t *natsTransport) Publish(subject string, payload []byte) error {
	return t.nc.Publish(subject, payload)
}

func (t *natsTransport) Flush() error {
	return t.nc.Flush()
}

func (t *natsTransport) Close() {
	t.nc.Close()
}

func (t *natsTransport) ProtocolType() sdkprotocol.TransportType {
	return sdkprotocol.TransportTypeNATS
}
