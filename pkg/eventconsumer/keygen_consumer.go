package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Maximum time to wait for a signing response.
	keygenResponseTimeout = 30 * time.Second
	// How often to poll for the reply message.
	keygenPollingInterval = 500 * time.Millisecond
)

// KeygenConsumer represents a consumer that processes signing events.
type KeygenConsumer interface {
	// Run starts the consumer and blocks until the provided context is canceled.
	Run(ctx context.Context) error
	// Close performs a graceful shutdown of the consumer.
	Close() error
}

// keygenConsumer implements KeygenConsumer.
type keygenConsumer struct {
	natsConn          *nats.Conn
	pubsub            messaging.PubSub
	jsBroker          messaging.MessageBroker
	peerRegistry      mpc.PeerRegistry
	keygenResultQueue messaging.MessageQueue

	// jsSub holds the JetStream subscription, so it can be cleaned up during Close().
	jsSub messaging.MessageSubscription
}

// NewKeygenConsumer returns a new instance of KeygenConsumer.
func NewKeygenConsumer(
	natsConn *nats.Conn,
	jsBroker messaging.MessageBroker,
	pubsub messaging.PubSub,
	peerRegistry mpc.PeerRegistry,
	keygenResultQueue messaging.MessageQueue,
) KeygenConsumer {
	return &keygenConsumer{
		natsConn:          natsConn,
		pubsub:            pubsub,
		jsBroker:          jsBroker,
		peerRegistry:      peerRegistry,
		keygenResultQueue: keygenResultQueue,
	}
}

func (sc *keygenConsumer) waitForAllPeersReadyToGenKey(ctx context.Context) error {

	logger.Info("KeygenConsumer: Waiting for all peers to be ready before consuming messages")

	ticker := time.NewTicker(readinessCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				return nil
			}
			return ctx.Err()
		case <-ticker.C:
			allPeersReady := sc.peerRegistry.ArePeersReady()

			if allPeersReady {
				logger.Info("KeygenConsumer: All peers are ready, proceeding to consume messages")
				return nil
			} else {
				logger.Info("KeygenConsumer: Waiting for all peers to be ready",
					"readyPeers", sc.peerRegistry.GetReadyPeersCount(),
					"totalPeers", sc.peerRegistry.GetTotalPeersCount())
			}
		}
	}
}

// Run subscribes to signing events and processes them until the context is canceled.
func (sc *keygenConsumer) Run(ctx context.Context) error {
	// Wait for sufficient peers before starting to consume messages
	if err := sc.waitForAllPeersReadyToGenKey(ctx); err != nil {
		if err == context.Canceled {
			return nil
		}
		return fmt.Errorf("failed to wait for sufficient peers: %w", err)
	}

	sub, err := sc.jsBroker.CreateSubscription(
		ctx,
		event.KeygenConsumerStream,
		event.KeygenRequestTopic,
		sc.handleKeygenEvent,
	)
	if err != nil {
		return fmt.Errorf("failed to subscribe to keygen events: %w", err)
	}
	sc.jsSub = sub
	logger.Info("SigningConsumer: Subscribed to keygen events")

	// Block until context cancellation.
	<-ctx.Done()
	logger.Info("KeygenConsumer: Context cancelled, shutting down")

	// When context is canceled, close subscription.
	return sc.Close()
}

func (sc *keygenConsumer) handleKeygenEvent(msg jetstream.Msg) {
	raw := msg.Data()
	var keygenMsg types.GenerateKeyMessage
	sessionID := msg.Headers().Get("SessionID")

	err := json.Unmarshal(raw, &keygenMsg)
	if err != nil {
		logger.Error("SigningConsumer: Failed to unmarshal keygen message", err)
		sc.handleKeygenError(keygenMsg, event.ErrorCodeUnmarshalFailure, err, sessionID)
		_ = msg.Ack()
		return
	}

	if !sc.peerRegistry.ArePeersReady() {
		logger.Warn("KeygenConsumer: Not all peers are ready to gen key, skipping message processing")
		sc.handleKeygenError(keygenMsg, event.ErrorCodeClusterNotReady, errors.New("not all peers are ready"), sessionID)
		_ = msg.Ack()
		return
	}

	// Create a reply inbox to receive the signing event response.
	replyInbox := nats.NewInbox()

	// Use a synchronous subscription for the reply inbox.
	replySub, err := sc.natsConn.SubscribeSync(replyInbox)
	if err != nil {
		logger.Error("KeygenConsumer: Failed to subscribe to reply inbox", err)
		_ = msg.Nak()
		return
	}
	defer func() {
		if err := replySub.Unsubscribe(); err != nil {
			logger.Warn("KeygenConsumer: Failed to unsubscribe from reply inbox", "error", err)
		}
	}()

	// Publish the signing event with the reply inbox.
	headers := map[string]string{
		"SessionID": uuid.New().String(),
	}
	if err := sc.pubsub.PublishWithReply(MPCGenerateEvent, replyInbox, msg.Data(), headers); err != nil {
		logger.Error("KeygenConsumer: Failed to publish signing event with reply", err)
		_ = msg.Nak()
		return
	}

	// Poll for the reply message until timeout.
	deadline := time.Now().Add(keygenResponseTimeout)
	for time.Now().Before(deadline) {
		replyMsg, err := replySub.NextMsg(keygenPollingInterval)
		if err != nil {
			// If timeout occurs, continue trying.
			if err == nats.ErrTimeout {
				continue
			}
			logger.Error("KeygenConsumer: Error receiving reply message", err)
			break
		}
		if replyMsg != nil {
			logger.Info("KeygenConsumer: Completed keygen event; reply received")
			if ackErr := msg.Ack(); ackErr != nil {
				logger.Error("KeygenConsumer: ACK failed", ackErr)
			}
			return
		}
	}

	logger.Warn("KeygenConsumer: Timeout waiting for keygen event response")
	_ = msg.Nak()
}

func (sc *keygenConsumer) handleKeygenError(keygenMsg types.GenerateKeyMessage, errorCode event.ErrorCode, err error, sessionID string) {
	keygenResult := event.KeygenResultEvent{
		ResultType:  event.ResultTypeError,
		ErrorCode:   string(errorCode),
		WalletID:    keygenMsg.WalletID,
		ErrorReason: err.Error(),
	}

	keygenResultBytes, err := json.Marshal(keygenResult)
	if err != nil {
		logger.Error("Failed to marshal keygen result event", err,
			"walletID", keygenResult.WalletID,
		)
		return
	}

	topic := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, keygenResult.WalletID)
	err = sc.keygenResultQueue.Enqueue(topic, keygenResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: buildIdempotentKey(keygenMsg.WalletID, sessionID, mpc.TypeGenerateWalletResultFmt),
	})
	if err != nil {
		logger.Error("Failed to enqueue keygen result event", err,
			"walletID", keygenMsg.WalletID,
		)
	}
}

// Close unsubscribes from the JetStream subject and cleans up resources.
func (sc *keygenConsumer) Close() error {
	if sc.jsSub != nil {
		if err := sc.jsSub.Unsubscribe(); err != nil {
			logger.Error("KeygenConsumer: Failed to unsubscribe from JetStream", err)
			return err
		}
		logger.Info("KeygenConsumer: Unsubscribed from JetStream")
	}
	return nil
}
