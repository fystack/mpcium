package messaging

import (
	"sync"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

type Subscription interface {
	Unsubscribe() error
}

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

type natsSubscription struct {
	subscription *nats.Subscription
}

func (ns *natsSubscription) Unsubscribe() error {
	return ns.subscription.Unsubscribe()
}

func NewNATSPubSub(natsConn *nats.Conn) PubSub {
	return &natsPubSub{
		natsConn: natsConn,
		handlers: make(map[string][]func(*nats.Msg)),
	}
}

func (n *natsPubSub) Publish(topic string, message []byte) error {
	logger.Info("[NATS] Publishing message", "topic", topic)

	// Invoke all handlers for the topic locally
	n.mu.Lock()
	defer n.mu.Unlock()

	handlers, ok := n.handlers[topic]
	if ok && len(handlers) != 0 {
		msgNats := &nats.Msg{
			Subject: topic,   // Required: the topic to publish to
			Data:    message, // The []byte payload
			// Reply:   reply,       // Optional: reply subject for request-response
			// Header:  make(nats.Header), // Optional: initialize headers if needed
		}
		for _, handler := range handlers {
			handler(msgNats)
		}
	} else {
		logger.Warn("[NATS] No handlers found for topic", "topic", topic)
	}

	// Publish the message to NATS with NoEcho option turned on
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

	return &natsSubscription{subscription: sub}, nil
}
