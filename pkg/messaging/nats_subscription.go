package messaging

import (
	"fmt"

	"github.com/nats-io/nats.go"
)

type Subscription interface {
	Unsubscribe() error
}

// a subscription can be made by pubsub or dicrectmessaging
type natsSubscription struct {
	subscription *nats.Subscription
	topic        string
	pubSub       *natsPubSub
	direct       *natsDirectMessaging
}

func (ns *natsSubscription) Unsubscribe() error {
	if ns.topic == "" {
		return fmt.Errorf("cannot cleanup handlers: topic is empty")
	}

	if ns.pubSub != nil {
		ns.pubSub.cleanupHandlers(ns.topic)
	}

	if ns.direct != nil {
		ns.direct.cleanupHandlers(ns.topic)
	}
	return ns.subscription.Unsubscribe()
}
