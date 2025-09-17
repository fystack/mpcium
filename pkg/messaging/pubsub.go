package messaging

import (
	"sync"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

type PubSub interface {
	Publish(topic string, message []byte) error
	PublishWithReply(topic, reply string, data []byte, headers map[string]string) error
	Subscribe(topic string, handler func(*nats.Msg)) (Subscription, error)
}

type natsPubSub struct {
	natsConn *nats.Conn
	handlers map[string][]func(*nats.Msg)
	mu       sync.Mutex
}

func NewNATSPubSub(natsConn *nats.Conn) PubSub {
	return &natsPubSub{
		natsConn: natsConn,
		handlers: make(map[string][]func(*nats.Msg)),
	}
}

func (n *natsPubSub) Publish(topic string, message []byte) error {
	logger.Info("[NATS] Publishing message", "topic", topic)

	// access local handlers for subscribed topics
	n.mu.Lock()
	defer n.mu.Unlock()

	handlers, ok := n.handlers[topic]
	if ok && len(handlers) != 0 {
		msgNats := &nats.Msg{
			Subject: topic,   // Required: the topic to publish to
			Data:    message, // The []byte payload
		}
		for _, handler := range handlers {
			handler(msgNats)
		}
	}

	return n.natsConn.Publish(topic, message)
}

func (n *natsPubSub) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	msg := &nats.Msg{
		Subject: topic,
		Reply:   reply,
		Data:    data,
		Header:  nats.Header{},
	}
	for k, v := range headers {
		msg.Header.Set(k, v)
	}

	// access local handlers for subscribed topics
	n.mu.Lock()
	defer n.mu.Unlock()

	handlers, ok := n.handlers[topic]
	if ok && len(handlers) != 0 {
		for _, handler := range handlers {
			handler(msg)
		}
	}

	err := n.natsConn.PublishMsg(msg)
	return err
}

func (n *natsPubSub) Subscribe(topic string, handler func(*nats.Msg)) (Subscription, error) {
	//Handle subscription: handle more fields in msg
	sub, err := n.natsConn.Subscribe(topic, func(msg *nats.Msg) {
		handler(msg)
	})
	if err != nil {
		return nil, err
	}

	n.mu.Lock()
	n.handlers[topic] = append(n.handlers[topic], handler)
	n.mu.Unlock()

	return &natsSubscription{subscription: sub, topic: topic, pubSub: n}, nil
}

func (n *natsPubSub) cleanupHandlers(topic string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.handlers, topic)
}
