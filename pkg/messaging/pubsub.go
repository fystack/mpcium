package messaging

import (
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

type Subscription interface {
	Unsubscribe() error
}

type PubSub interface {
	Publish(topic string, message []byte, headers map[string]string) error
	PublishWithReply(topic, reply string, data []byte, headers map[string]string) error
	Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error)
}

type natsPubSub struct {
	natsConn *nats.Conn
}

type natsSubscription struct {
	subscription *nats.Subscription
}

func (ns *natsSubscription) Unsubscribe() error {
	return ns.subscription.Unsubscribe()
}

func NewNATSPubSub(natsConn *nats.Conn) PubSub {
	return &natsPubSub{natsConn}
}

func (n *natsPubSub) Publish(topic string, message []byte, headers map[string]string) error {
	logger.Debug("[NATS] Publishing message", "topic", topic)
	msg := &nats.Msg{
		Subject: topic,
		Data:    message,
		Header:  nats.Header{},
	}
	applyHeaders(msg.Header, headers)
	return n.natsConn.PublishMsg(msg)
}

func (n *natsPubSub) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	msg := &nats.Msg{
		Subject: topic,
		Reply:   reply,
		Data:    data,
		Header:  nats.Header{},
	}
	applyHeaders(msg.Header, headers)
	err := n.natsConn.PublishMsg(msg)
	return err
}

func (n *natsPubSub) Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error) {
	//Handle subscription: handle more fields in msg
	sub, err := n.natsConn.Subscribe(topic, func(msg *nats.Msg) {
		handler(msg)
	})
	if err != nil {
		return nil, err
	}

	return &natsSubscription{subscription: sub}, nil
}

func applyHeaders(dst nats.Header, headers map[string]string) {
	for k, v := range headers {
		dst.Set(k, v)
	}
}
