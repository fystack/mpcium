package taurus

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/taurusgroup/multi-party-sig/pkg/party"

	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

type NATSTransport struct {
	selfID string
	wallet string
	pubsub messaging.PubSub

	composeBroadcast func() string
	composeDirect    func(nodeID string) string

	inbox  chan Msg
	doneCh chan struct{}
	errCh  chan error

	mu      sync.Mutex
	subs    []messaging.Subscription
	closeMu sync.Once
}

// NewNATSTransport creates a transport bound to a walletID and party.
func NewNATSTransport(walletID string, self party.ID, pubsub messaging.PubSub) *NATSTransport {
	t := &NATSTransport{
		selfID: string(self),
		wallet: walletID,
		pubsub: pubsub,
		inbox:  make(chan Msg, 128),
		doneCh: make(chan struct{}),
		errCh:  make(chan error, 8),

		composeBroadcast: func() string {
			return fmt.Sprintf("mpc:broadcast:%s", walletID)
		},
		composeDirect: func(nodeID string) string {
			return fmt.Sprintf("mpc:direct:%s:%s", nodeID, walletID)
		},
	}

	// subscribe broadcast
	bcastTopic := t.composeBroadcast()
	bcast, err := pubsub.Subscribe(bcastTopic, func(m *nats.Msg) {
		t.handleRaw(m.Data)
	})
	if err == nil {
		t.subs = append(t.subs, bcast)
	} else {
		t.pushErr(err)
	}

	// subscribe direct
	directTopic := t.composeDirect(t.selfID)
	direct, err := pubsub.Subscribe(directTopic, func(m *nats.Msg) {
		t.handleRaw(m.Data)
	})
	if err == nil {
		t.subs = append(t.subs, direct)
	} else {
		t.pushErr(err)
	}

	logger.Info("✅ NATSTransport listening",
		"wallet", walletID,
		"broadcast", bcastTopic,
		"direct", directTopic)

	return t
}

// --- Transport interface ---

func (t *NATSTransport) Send(to string, msg Msg) error {
	// Marshal the message
	data, err := encoding.StructToJsonBytes(&msg)
	if err != nil {
		return err
	}

	if msg.IsBroadcast {
		// publish to broadcast topic
		topic := t.composeBroadcast()
		return t.pubsub.Publish(topic, data)
	}

	// unicast to "to"
	topic := t.composeDirect(to)
	return t.pubsub.Publish(topic, data)
}

func (t *NATSTransport) Inbox() <-chan Msg     { return t.inbox }
func (t *NATSTransport) Done() <-chan struct{} { return t.doneCh }

func (t *NATSTransport) Close() error {
	t.closeMu.Do(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		for i, sub := range t.subs {
			if sub != nil {
				_ = sub.Unsubscribe()
				logger.Debug("✅ unsubscribed", "index", i, "wallet", t.wallet)
			}
		}
		close(t.inbox)
		close(t.errCh)
		close(t.doneCh)
		logger.Info("🛑 NATSTransport closed", "wallet", t.wallet)
	})
	return nil
}

// --- Internal helpers ---

func (t *NATSTransport) handleRaw(data []byte) {
	var m Msg
	if err := json.Unmarshal(data, &m); err != nil {
		t.pushErr(fmt.Errorf("unmarshal inbound: %w", err))
		return
	}
	if m.From == t.selfID {
		return // skip self
	}
	select {
	case t.inbox <- m:
	default:
		logger.Warn("⚠️ dropping inbound message, inbox full", "wallet", t.wallet)
	}
}

func (t *NATSTransport) pushErr(err error) {
	select {
	case t.errCh <- err:
	default:
		logger.Warn("⚠️ dropping error (buffer full)", "wallet", t.wallet)
	}
}
