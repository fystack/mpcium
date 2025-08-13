package messaging

import (
	"fmt"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

type DirectMessaging interface {
	Listen(topic string, handler func(data []byte)) (Subscription, error)
	SendToOther(topic string, data []byte) error
	SendToSelf(topic string, data []byte) error
}

type natsDirectMessaging struct {
	natsConn *nats.Conn
	handlers map[string][]func([]byte)
	mu       sync.Mutex
}

func NewNatsDirectMessaging(natsConn *nats.Conn) DirectMessaging {
	return &natsDirectMessaging{
		natsConn: natsConn,
		handlers: make(map[string][]func([]byte)),
	}
}

// SendToSelf locally sends a message to the same node, invoking all handlers for the topic
// avoiding mediating through the message layer.
func (d *natsDirectMessaging) SendToSelf(topic string, message []byte) error {
	d.mu.Lock()
	handlers, ok := d.handlers[topic]
	d.mu.Unlock()

	if !ok || len(handlers) == 0 {
		return fmt.Errorf("no handlers found for topic %s", topic)
	}

	for _, handler := range handlers {
		handler(message)
	}

	return nil
}

func (d *natsDirectMessaging) SendToOther(topic string, message []byte) error {
	return retry.Do(
		func() error {
			_, err := d.natsConn.Request(topic, message, 3*time.Second)
			if err != nil {
				return err
			}
			return nil
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			logger.Error("Failed to send direct message", err, "attempt", n+1, "topic", topic)
		}),
	)
}

func (d *natsDirectMessaging) Listen(topic string, handler func(data []byte)) (Subscription, error) {
	sub, err := d.natsConn.Subscribe(topic, func(m *nats.Msg) {
		handler(m.Data)
		if err := m.Respond([]byte("OK")); err != nil {
			logger.Error("Failed to respond to message", err)
		}
	})
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.handlers[topic] = append(d.handlers[topic], handler)
	d.mu.Unlock()

	return &natsSubscription{subscription: sub}, nil
}
