package taurus

import (
	"fmt"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Act string

const (
	ActKeygen  Act = "keygen"
	ActSign    Act = "sign"
	ActReshare Act = "reshare"
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(to string, walletID string) string
}

type NATSTransport struct {
	selfID        string
	wallet        string
	act           Act
	topicComposer *TopicComposer
	pubsub        messaging.PubSub
	direct        messaging.DirectMessaging
	identityStore identity.Store
	inbox         chan types.TaurusMessage
	done          chan struct{}
	subs          []messaging.Subscription
	closeMu       sync.Once
}

func NewNATSTransport(
	walletID string,
	self party.ID,
	act Act,
	pubsub messaging.PubSub,
	direct messaging.DirectMessaging,
	identityStore identity.Store,
) *NATSTransport {
	t := &NATSTransport{
		selfID:        string(self),
		wallet:        walletID,
		act:           act,
		pubsub:        pubsub,
		direct:        direct,
		identityStore: identityStore,
		topicComposer: &TopicComposer{
			ComposeBroadcastTopic: func() string {
				return fmt.Sprintf("%s:broadcast:cmp:%s", act, walletID)
			},
			ComposeDirectTopic: func(to string, walletID string) string {
				return fmt.Sprintf("%s:direct:cmp:%s:%s", act, to, walletID)
			},
		},
		inbox: make(chan types.TaurusMessage, 128),
		done:  make(chan struct{}),
	}

	bcastTopic := t.topicComposer.ComposeBroadcastTopic()
	if sub, err := pubsub.Subscribe(bcastTopic, func(msg *nats.Msg) {
		t.handle(msg.Data)
	}); err == nil {
		t.subs = append(t.subs, sub)
	}

	directTopic := t.topicComposer.ComposeDirectTopic(t.selfID, walletID)
	if sub, err := direct.Listen(directTopic, t.handle); err == nil {
		t.subs = append(t.subs, sub)
	}

	logger.Debug(
		"NATS Transport listening",
		"wallet",
		walletID,
		"broadcast",
		bcastTopic,
		"direct",
		directTopic,
	)
	return t
}

func (t *NATSTransport) Send(to string, msg types.TaurusMessage) error {
	// use AEAD encryption for each message so NATs server learns nothing
	if t.identityStore != nil {
		cipher, err := t.identityStore.SignTaurusMessage(&msg)
		if err != nil {
			return err
		}
		msg.Signature = cipher
	}
	data, err := encoding.StructToJsonBytes(&msg)
	if err != nil {
		return err
	}
	if msg.IsBroadcast {
		topic := t.topicComposer.ComposeBroadcastTopic()
		return t.pubsub.Publish(topic, data)
	}

	// Use direct messaging for unicast with retry
	topic := t.topicComposer.ComposeDirectTopic(to, t.wallet)
	if to == t.selfID {
		return t.direct.SendToSelf(topic, data)
	}

	return t.direct.SendToOtherWithRetry(topic, data, messaging.RetryConfig{
		RetryAttempt:       3,
		ExponentialBackoff: true,
		Delay:              50 * time.Millisecond,
		OnRetry: func(n uint, err error) {
			logger.Warn("Retry sending", "to", to, "attempt", n+1, "err", err.Error())
		},
	})
}

func (t *NATSTransport) Inbox() <-chan types.TaurusMessage { return t.inbox }
func (t *NATSTransport) Done() <-chan struct{}             { return t.done }

func (t *NATSTransport) Close() error {
	t.closeMu.Do(func() {
		for _, sub := range t.subs {
			if sub != nil {
				_ = sub.Unsubscribe()
			}
		}
		close(t.inbox)
		close(t.done)
		logger.Debug("NATSTransport closed", "wallet", t.wallet)
	})
	return nil
}

func (t *NATSTransport) handle(data []byte) {
	var msg types.TaurusMessage
	if err := encoding.JsonBytesToStruct(data, &msg); err != nil {
		return
	}
	if t.identityStore != nil {
		if err := t.identityStore.VerifyTaurusMessage(&msg); err != nil {
			logger.Warn("failed to verify message", "err", err.Error())
			return
		}
	}
	if msg.From == t.selfID {
		return
	}
	select {
	case t.inbox <- msg:
	default:
		logger.Warn("dropping inbound message, inbox full", "wallet", t.wallet)
	}
}
