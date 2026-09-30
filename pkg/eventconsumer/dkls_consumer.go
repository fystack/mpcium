//go:build dkls

package eventconsumer

import (
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/dkls"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

const dklsSessionTTL = 10 * time.Minute

type DklsConsumer struct {
	service            *dkls.Service
	pubsub             messaging.PubSub
	identityStore      identity.Store
	genKeyResultQueue  messaging.MessageQueue
	signingResultQueue messaging.MessageQueue
	threshold          int
	sessions           *sessionTracker

	keygenSub  messaging.Subscription
	signingSub messaging.Subscription
}

func NewDklsConsumer(
	service *dkls.Service,
	pubsub messaging.PubSub,
	identityStore identity.Store,
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	threshold int,
) *DklsConsumer {
	return &DklsConsumer{
		service:            service,
		pubsub:             pubsub,
		identityStore:      identityStore,
		genKeyResultQueue:  genKeyResultQueue,
		signingResultQueue: signingResultQueue,
		threshold:          threshold,
		sessions:           newSessionTracker(dklsSessionTTL),
	}
}

func (c *DklsConsumer) Run() {
	// Handlers block for the whole protocol and NATS runs one subscription's callbacks serially.
	c.keygenSub = c.subscribe(MPCDklsGenerateEvent, c.handleKeygen)
	c.signingSub = c.subscribe(MPCDklsSignEvent, c.handleSign)
	logger.Info("DklsConsumer: subscribed to keygen/signing events")
}

func (c *DklsConsumer) subscribe(subject string, handle func(*nats.Msg)) messaging.Subscription {
	sub, err := c.pubsub.Subscribe(subject, func(natMsg *nats.Msg) { go handle(natMsg) })
	if err != nil {
		logger.Fatal("DklsConsumer: failed to subscribe to "+subject, err)
	}
	return sub
}

func (c *DklsConsumer) Close() error {
	for _, sub := range []messaging.Subscription{c.keygenSub, c.signingSub} {
		if sub != nil {
			_ = sub.Unsubscribe()
		}
	}
	return nil
}

func (c *DklsConsumer) authorized(msg types.InitiatorMessage) bool {
	if err := c.identityStore.VerifyInitiatorMessage(msg); err != nil {
		logger.Error("DklsConsumer: failed to verify initiator message", err)
		return false
	}
	if err := c.identityStore.AuthorizeInitiatorMessage(msg); err != nil {
		logger.Error("DklsConsumer: failed to authorize initiator message", err)
		return false
	}
	return true
}

func (c *DklsConsumer) handleKeygen(natMsg *nats.Msg) {
	var msg types.GenerateKeyMessage
	if err := json.Unmarshal(natMsg.Data, &msg); err != nil || !c.authorized(&msg) {
		return
	}

	walletID := msg.WalletID
	sessionKey := "keygen:" + walletID
	if !c.sessions.begin(sessionKey) {
		logger.Warn("DklsConsumer: duplicate keygen request", "walletID", walletID)
		c.sendReply(natMsg)
		return
	}

	result := event.KeygenResultEvent{WalletID: walletID}
	keys, err := c.service.Keygen(walletID, c.threshold)
	if err != nil {
		c.sessions.release(sessionKey)
		logger.Error("DklsConsumer: keygen failed", err, "walletID", walletID)
		result.ResultType = event.ResultTypeError
		result.ErrorReason = err.Error()
		result.ErrorCode = string(event.GetErrorCodeFromError(err))
	} else {
		result.ResultType = event.ResultTypeSuccess
		result.DKLSPubKey = keys.PubKey
		result.DKLSChainCode = keys.ChainCode
	}

	c.publishKeygenResult(natMsg, result)
	c.sendReply(natMsg)
}

func (c *DklsConsumer) handleSign(natMsg *nats.Msg) {
	var msg types.SignTxMessage
	if err := json.Unmarshal(natMsg.Data, &msg); err != nil || !c.authorized(&msg) {
		return
	}

	sessionKey := msg.WalletID + ":" + msg.TxID
	if !c.sessions.begin(sessionKey) {
		logger.Warn("DklsConsumer: duplicate signing request", "walletID", msg.WalletID, "txID", msg.TxID)
		c.sendReply(natMsg)
		return
	}

	sig, err := c.service.Sign(msg.WalletID, msg.TxID, msg.Tx, msg.DerivationPath)
	switch {
	case errors.Is(err, dkls.ErrNotEnoughSigners):
		// No reply, so the un-ACKed JetStream message is redelivered later.
		c.sessions.release(sessionKey)
		logger.Info("DklsConsumer: RETRY LATER: not enough participants to sign", "walletID", msg.WalletID, "txID", msg.TxID)
		return
	case errors.Is(err, dkls.ErrNotParticipant), errors.Is(err, dkls.ErrNotSelected):
		c.sessions.release(sessionKey)
		logger.Debug("DklsConsumer: this node does not take part in the signing", "walletID", msg.WalletID, "txID", msg.TxID)
		return
	case err != nil:
		c.sessions.release(sessionKey)
		logger.Error("DklsConsumer: sign failed", err, "walletID", msg.WalletID, "txID", msg.TxID)
		c.publishSignResult(natMsg, event.SigningResultEvent{
			ResultType:          event.ResultTypeError,
			NetworkInternalCode: msg.NetworkInternalCode,
			WalletID:            msg.WalletID,
			TxID:                msg.TxID,
			ErrorCode:           event.GetErrorCodeFromError(err),
			ErrorReason:         err.Error(),
		})
		c.sendReply(natMsg)
		return
	}

	c.publishSignResult(natMsg, event.SigningResultEvent{
		ResultType:          event.ResultTypeSuccess,
		NetworkInternalCode: msg.NetworkInternalCode,
		WalletID:            msg.WalletID,
		TxID:                msg.TxID,
		R:                   sig.R[:],
		S:                   sig.S[:],
		SignatureRecovery:   []byte{sig.Recovery},
		Signature:           slices.Concat(sig.R[:], sig.S[:]),
	})
	logger.Info("[SIGN] DKLS sign successfully", "walletID", msg.WalletID, "txID", msg.TxID)
	c.sendReply(natMsg)
}

func (c *DklsConsumer) publishKeygenResult(natMsg *nats.Msg, result event.KeygenResultEvent) {
	payload, err := json.Marshal(result)
	if err != nil {
		logger.Error("DklsConsumer: failed to marshal keygen result", err)
		return
	}
	subject := event.KeygenResultSubject(natMsg.Header.Get(event.ClientIDHeader), result.WalletID)
	opts := &messaging.EnqueueOptions{IdempotententKey: composeKeygenIdempotentKey("dkls:"+result.WalletID, natMsg)}
	if err := c.genKeyResultQueue.Enqueue(subject, payload, opts); err != nil {
		logger.Error("DklsConsumer: failed to enqueue keygen result", err)
		return
	}
	if result.ResultType == event.ResultTypeSuccess {
		logger.Info("[COMPLETED KEY GEN] DKLS keygen completed", "walletID", result.WalletID)
	}
}

func (c *DklsConsumer) publishSignResult(natMsg *nats.Msg, result event.SigningResultEvent) {
	payload, err := json.Marshal(result)
	if err != nil {
		logger.Error("DklsConsumer: failed to marshal signing result", err)
		return
	}
	subject := event.SigningResultSubject(natMsg.Header.Get(event.ClientIDHeader))
	opts := &messaging.EnqueueOptions{IdempotententKey: composeSigningIdempotentKey(result.TxID, natMsg)}
	if err := c.signingResultQueue.Enqueue(subject, payload, opts); err != nil {
		logger.Error("DklsConsumer: failed to enqueue signing result", err)
	}
}

// Without a reply the JetStream wrapper consumer times out and redelivers.
func (c *DklsConsumer) sendReply(natMsg *nats.Msg) {
	if natMsg.Reply == "" {
		return
	}
	if err := c.pubsub.Publish(natMsg.Reply, natMsg.Data, nil); err != nil {
		logger.Error("DklsConsumer: failed to reply message", err, "reply", natMsg.Reply)
	}
}

// Finished requests stay tracked for the TTL so JetStream redeliveries are still dropped.
type sessionTracker struct {
	mu        sync.Mutex
	ttl       time.Duration
	seen      map[string]time.Time
	lastSweep time.Time
}

func newSessionTracker(ttl time.Duration) *sessionTracker {
	return &sessionTracker{ttl: ttl, seen: make(map[string]time.Time), lastSweep: time.Now()}
}

func (t *sessionTracker) begin(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.sweep(now)
	if _, dup := t.seen[key]; dup {
		return false
	}
	t.seen[key] = now
	return true
}

func (t *sessionTracker) release(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, key)
}

func (t *sessionTracker) sweep(now time.Time) {
	if now.Sub(t.lastSweep) < t.ttl/2 {
		return
	}
	t.lastSweep = now
	for key, started := range t.seen {
		if now.Sub(started) > t.ttl {
			delete(t.seen, key)
		}
	}
}
