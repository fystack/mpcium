package eventconsumer

import (
	"context"
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
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
	natsConn     *nats.Conn
	pubsub       messaging.PubSub
	jsBroker     messaging.MessageBroker
	peerRegistry mpc.PeerRegistry
	mpcThreshold int

	// jsSub holds the JetStream subscription, so it can be cleaned up during Close().
	jsSub messaging.Subscription
}

// NewKeygenConsumer returns a new instance of KeygenConsumer.
func NewKeygenConsumer(natsConn *nats.Conn, jsBroker messaging.MessageBroker, pubsub messaging.PubSub, peerRegistry mpc.PeerRegistry) KeygenConsumer {
	return &keygenConsumer{
		natsConn:     natsConn,
		pubsub:       pubsub,
		jsBroker:     jsBroker,
		peerRegistry: peerRegistry,
	}
}

func (sc *keygenConsumer) waitForAllPeersReadyToGenKey(ctx context.Context) error {

	logger.Info("KeygenConsumer: Waiting for all peers to be ready before consuming messages")

	ticker := time.NewTicker(readinessCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
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
		return fmt.Errorf("failed to wait for sufficient peers: %w", err)
	}

	sub, err := sc.jsBroker.CreateSubscription(
		ctx,
		event.KeygenConsumerStream,
		event.KeygenRequestTopic,
		sc.handleKeygenEvent,
	)
	if err != nil {
		return fmt.Errorf("failed to subscribe to signing events: %w", err)
	}
	sc.jsSub = sub
	logger.Info("SigningConsumer: Subscribed to signing events")

	// Block until context cancellation.
	<-ctx.Done()
	logger.Info("KeygenConsumer: Context cancelled, shutting down")

	// When context is canceled, close subscription.
	return sc.Close()
}

// The handleSigningEvent function in sign_consumer.go acts as a bridge between the JetStream-based event queue and the MPC (Multi-Party Computation) signing system
// Creates a reply channel: It generates a unique inbox address using nats.NewInbox() to receive the signing response.
// Sets up response handling: It creates a synchronous subscription to listen for replies on this inbox.
// Forwards the signing request: It publishes the original signing event data to the MPCSigningEventTopic with the reply inbox attached, which triggers the MPC signing process.
// Polls for completion: It enters a polling loop that checks for a reply message, continuing until either:
// A reply is received (successful signing)
// An error occurs (failed signing)
// The timeout is reached (30 seconds)
// Completes the transaction: It either acknowledges (Ack) the message if signing was successful or negatively acknowledges (Nak) it if there was a timeout or error.
// MPC Session Interaction
// The signing consumer doesn't directly interact with MPC sessions. Instead:
// It publishes the signing request to the MPCSigningEventTopic, which is consumed by the eventconsumer.consumeTxSigningEvent handler.
// This handler creates the appropriate signing session (SigningSession for ECDSA or EDDSASigningSession for EdDSA) via the MPC node's creation methods.
// The MPC signing sessions manage the distributed cryptographic operations across multiple nodes, handling message routing, party updates, and signature verification.
// When signing completes, the session publishes the result to a queue and calls the onSuccess callback, which sends a reply to the inbox that the KeygenConsumer is monitoring.
// The reply signals completion, allowing the KeygenConsumer to acknowledge the original message.
func (sc *keygenConsumer) handleKeygenEvent(msg jetstream.Msg) {

	if !sc.peerRegistry.ArePeersReady() {
		logger.Warn("KeygenConsumer: Not all peers are ready to sign, skipping message processing")
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
	if err := sc.pubsub.PublishWithReply(MPCGenerateEvent, replyInbox, msg.Data()); err != nil {
		logger.Error("KeygenConsumer: Failed to publish signing event with reply", err)
		_ = msg.Nak()
		return
	}

	// Poll for the reply message until timeout.
	deadline := time.Now().Add(signingResponseTimeout)
	for time.Now().Before(deadline) {
		replyMsg, err := replySub.NextMsg(signingPollingInterval)
		if err != nil {
			// If timeout occurs, continue trying.
			if err == nats.ErrTimeout {
				continue
			}
			logger.Error("KeygenConsumer: Error receiving reply message", err)
			break
		}
		if replyMsg != nil {
			logger.Info("KeygenConsumer: Completed signing event; reply received")
			if ackErr := msg.Ack(); ackErr != nil {
				logger.Error("KeygenConsumer: ACK failed", ackErr)
			}
			return
		}
	}

	logger.Warn("KeygenConsumer: Timeout waiting for signing event response")
	_ = msg.Nak()
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
