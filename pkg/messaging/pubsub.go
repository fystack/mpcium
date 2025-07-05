package messaging

import (
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type Subscription interface {
	Unsubscribe() error
}

type PubSub interface {
	Publish(topic string, message []byte) error
	PublishWithReply(topic, reply string, data []byte) error
	Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error)
}

type natsPubSub struct {
	natsConn *nats.Conn
}

type natsSubscription struct {
	subscription *nats.Subscription
}

type jetstreamSubscription struct {
	consumer jetstream.Consumer
}

func (ns *natsSubscription) Unsubscribe() error {
	return ns.subscription.Unsubscribe()
}

func (js *jetstreamSubscription) Unsubscribe() error {
	return nil
}

func NewNATSPubSub(natsConn *nats.Conn) PubSub {
	return &natsPubSub{natsConn}
}

func (n *natsPubSub) Publish(topic string, message []byte) error {
	logger.Debug("[NATS] Publishing message", "topic", topic)
	return n.natsConn.Publish(topic, message)
}

func (n *natsPubSub) PublishWithReply(topic, reply string, data []byte) error {
	return n.natsConn.PublishMsg(&nats.Msg{
		Subject: topic,
		Reply:   reply,
		Data:    data,
	})
}

func (n *natsPubSub) Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error) {
	// TODO: Handle subscription
	// handle more fields in msg
	sub, err := n.natsConn.Subscribe(topic, func(msg *nats.Msg) {
		handler(msg)
	})
	if err != nil {
		return nil, err
	}

	return &natsSubscription{subscription: sub}, nil
}
