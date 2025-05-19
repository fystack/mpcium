package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

const (
	MPCGenerateEvent  = "mpc:generate"
	MPCSignEvent      = "mpc:sign"
	MPCResharingEvent = "mpc:reshare"
)

type EventConsumer interface {
	Run()
	Close() error
}

type eventConsumer struct {
	node         *mpc.Node
	pubsub       messaging.PubSub
	mpcThreshold int

	genKeySucecssQueue   messaging.MessageQueue
	signingResultQueue   messaging.MessageQueue
	resharingResultQueue messaging.MessageQueue

	keyGenerationSub messaging.Subscription
	signingSub       messaging.Subscription
	resharingSub     messaging.Subscription
	identityStore    identity.Store

	// Track active sessions with timestamps for cleanup
	activeSessions  map[string]time.Time // Maps "walletID-txID" to creation time
	sessionsLock    sync.RWMutex
	cleanupInterval time.Duration // How often to run cleanup
	sessionTimeout  time.Duration // How long before a session is considered stale
	cleanupStopChan chan struct{} // Signal to stop cleanup goroutine
}

func NewEventConsumer(
	node *mpc.Node,
	pubsub messaging.PubSub,
	genKeySucecssQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	resharingResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	ec := &eventConsumer{
		node:                 node,
		pubsub:               pubsub,
		genKeySucecssQueue:   genKeySucecssQueue,
		signingResultQueue:   signingResultQueue,
		resharingResultQueue: resharingResultQueue,
		activeSessions:       make(map[string]time.Time),
		cleanupInterval:      5 * time.Minute,  // Run cleanup every 5 minutes
		sessionTimeout:       30 * time.Minute, // Consider sessions older than 30 minutes stale
		cleanupStopChan:      make(chan struct{}),
		mpcThreshold:         viper.GetInt("mpc_threshold"),
		identityStore:        identityStore,
	}

	// Start background cleanup goroutine
	go ec.sessionCleanupRoutine()

	return ec
}

func (ec *eventConsumer) Run() {
	err := ec.consumeKeyGenerationEvent()
	if err != nil {
		log.Fatal("Failed to consume key reconstruction event", err)
	}

	err = ec.consumeTxSigningEvent()
	if err != nil {
		log.Fatal("Failed to consume tx signing event", err)
	}

	err = ec.consumeResharingEvent()
	if err != nil {
		log.Fatal("Failed to consume resharing event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		raw := natMsg.Data
		var msg types.GenerateKeyMessage
		err := json.Unmarshal(raw, &msg)
		if err != nil {
			logger.Error("Failed to unmarshal signing message", err)
			return
		}
		logger.Info("Received key generation event", "msg", msg)

		err = ec.identityStore.VerifyInitiatorMessage(&msg)
		if err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		walletID := msg.WalletID
		session, err := ec.node.CreateKeyGenSession(walletID, ec.mpcThreshold, ec.genKeySucecssQueue)
		if err != nil {
			logger.Error("Failed to create key generation session", err, "walletID", walletID)
			return
		}
		eddsaSession, err := ec.node.CreateEDDSAKeyGenSession(walletID, ec.mpcThreshold, ec.genKeySucecssQueue)
		if err != nil {
			logger.Error("Failed to create key generation session", err, "walletID", walletID)
			return
		}

		session.Init()
		eddsaSession.Init()

		ctx, done := context.WithCancel(context.Background())
		ctxEddsa, doneEddsa := context.WithCancel(context.Background())

		successEvent := &mpc.KeygenSuccessEvent{
			WalletID: walletID,
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			for {
				select {
				case <-ctx.Done():
					successEvent.ECDSAPubKey = session.GetPubKeyResult()
					wg.Done()
					return
				case err := <-session.ErrCh:
					logger.Error("Keygen session error", err)
				}
			}
		}()

		go func() {
			for {
				select {
				case <-ctxEddsa.Done():
					successEvent.EDDSAPubKey = eddsaSession.GetPubKeyResult()
					wg.Done()
					return
				case err := <-eddsaSession.ErrCh:
					logger.Error("Keygen session error", err)
				}
			}
		}()

		session.ListenToIncomingMessageAsync()
		eddsaSession.ListenToIncomingMessageAsync()
		// TODO: replace sleep with distributed lock
		time.Sleep(1 * time.Second)

		go session.GenerateKey(done)
		go eddsaSession.GenerateKey(doneEddsa)

		wg.Wait()
		logger.Info("Closing session successfully!", "event", successEvent)

		successEventBytes, err := json.Marshal(successEvent)
		if err != nil {
			logger.Error("Failed to marshal keygen success event", err)
			return
		}

		err = ec.genKeySucecssQueue.Enqueue(fmt.Sprintf(mpc.TypeGenerateWalletSuccess, walletID), successEventBytes, &messaging.EnqueueOptions{
			IdempotententKey: fmt.Sprintf(mpc.TypeGenerateWalletSuccess, walletID),
		})
		if err != nil {
			logger.Error("Failed to publish key generation success message", err)
			return
		}

		logger.Info("[COMPLETED KEY GEN] Key generation completed successfully", "walletID", walletID)

	})

	ec.keyGenerationSub = sub
	if err != nil {
		return err
	}
	return nil
}

func (ec *eventConsumer) consumeTxSigningEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCSignEvent, func(natMsg *nats.Msg) {
		raw := natMsg.Data
		var msg types.SignTxMessage
		err := json.Unmarshal(raw, &msg)
		if err != nil {
			logger.Error("Failed to unmarshal signing message", err)
			return
		}

		err = ec.identityStore.VerifyInitiatorMessage(&msg)
		if err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		logger.Info(
			"Received signing event",
			"waleltID",
			msg.WalletID,
			"type",
			msg.KeyType,
			"tx",
			msg.TxID,
			"Id",
			ec.node.ID(),
		)

		// Check for duplicate session and track if new
		if ec.checkDuplicateSession(msg.WalletID, msg.TxID) {
			natMsg.Term()
			return
		}

		var session mpc.ISigningSession
		switch msg.KeyType {
		case types.KeyTypeSecp256k1:
			session, err = ec.node.CreateSigningSession(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				ec.mpcThreshold,
				ec.signingResultQueue,
			)
		case types.KeyTypeEd25519:
			session, err = ec.node.CreateEDDSASigningSession(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				ec.mpcThreshold,
				ec.signingResultQueue,
			)

		}

		if err != nil {
			ec.handleSigningSessionError(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				err,
				"Failed to create signing session",
				natMsg,
			)
			return
		}

		txBigInt := new(big.Int).SetBytes(msg.Tx)
		err = session.Init(txBigInt)
		if err != nil {
			if errors.Is(err, mpc.ErrNotEnoughParticipants) {
				logger.Info("RETRY LATER: Not enough participants to sign")
				//Return for retry later
				return
			}
			ec.handleSigningSessionError(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				err,
				"Failed to init signing session",
				natMsg,
			)
			return
		}

		// Mark session as already processed
		ec.addSession(msg.WalletID, msg.TxID)

		ctx, done := context.WithCancel(context.Background())
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case err := <-session.ErrChan():
					if err != nil {
						ec.handleSigningSessionError(
							msg.WalletID,
							msg.TxID,
							msg.NetworkInternalCode,
							err,
							"Failed to sign tx",
							natMsg,
						)
						return
					}
				}
			}
		}()

		session.ListenToIncomingMessageAsync()
		// TODO: use consul distributed lock here, only sign after all nodes has already completed listing to incoming message async
		// The purpose of the sleep is to be ensuring that the node has properly set up its message listeners
		// before it starts the signing process. If the signing process starts sending messages before other nodes
		// have set up their listeners, those messages might be missed, potentially causing the signing process to fail.
		// One solution:
		// The messaging includes mechanisms for direct point-to-point communication (in point2point.go).
		// The nodes could explicitly coordinate through request-response patterns before starting signing
		time.Sleep(1 * time.Second)

		onSuccess := func(data []byte) {
			done()
			if natMsg.Reply != "" {
				err = ec.pubsub.Publish(natMsg.Reply, data)
				if err != nil {
					logger.Error("Failed to publish reply", err)
				} else {
					logger.Info("Reply to the original message", "reply", natMsg.Reply)
				}
			}
		}
		go session.Sign(onSuccess)
	})

	ec.signingSub = sub
	if err != nil {
		return err
	}

	return nil
}

func (ec *eventConsumer) handleSigningSessionError(walletID, txID, NetworkInternalCode string, err error, errMsg string, natMsg *nats.Msg) {
	logger.Error("Signing session error", err, "walletID", walletID, "txID", txID, "error", errMsg)
	signingResult := event.SigningResultEvent{
		ResultType:          event.SigningResultTypeError,
		NetworkInternalCode: NetworkInternalCode,
		WalletID:            walletID,
		TxID:                txID,
		ErrorReason:         errMsg,
	}

	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error("Failed to marshal signing result event", err)
		return
	}

	natMsg.Ack()
	err = ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signingResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: txID,
	})
	if err != nil {
		logger.Error("Failed to publish signing result event", err)
		return
	}
}

func (ec *eventConsumer) consumeResharingEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCResharingEvent, func(natMsg *nats.Msg) {
		raw := natMsg.Data
		var msg types.ResharingMessage
		err := json.Unmarshal(raw, &msg)
		if err != nil {
			logger.Error("Failed to unmarshal resharing message", err)
			return
		}
		logger.Info("Received resharing event", "walletID", msg.WalletID, "newThreshold", msg.NewThreshold)

		err = ec.identityStore.VerifyInitiatorMessage(&msg)
		if err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		walletID := msg.WalletID
		newThreshold := msg.NewThreshold

		// Get new participants
		readyPeerIDs := ec.node.GetReadyPeersIncludeSelf()
		if len(readyPeerIDs) < newThreshold+1 {
			logger.Error("Not enough peers for resharing", nil, "expected", newThreshold+1, "got", len(readyPeerIDs))
			return
		}

		var oldPSession, newPSession mpc.IResharingSession

		switch msg.KeyType {
		case types.KeyTypeSecp256k1:
			// Create resharing oldPSession
			oldPSession, err = ec.node.CreateECDSAResharingSession(walletID, true, readyPeerIDs, newThreshold, ec.resharingResultQueue)
			if err != nil {
				logger.Error("Failed to create resharing session", err)
				return
			}
			newPSession, err = ec.node.CreateECDSAResharingSession(walletID, false, readyPeerIDs, newThreshold, ec.resharingResultQueue)
			if err != nil {
				logger.Error("Failed to create resharing session", err)
				return
			}
		case types.KeyTypeEd25519:
			// Create resharing oldPSession
			oldPSession, err = ec.node.CreeateEDDSAResharingSession(walletID, true, readyPeerIDs, newThreshold, ec.resharingResultQueue)
			if err != nil {
				logger.Error("Failed to create resharing session", err)
				return
			}
			newPSession, err = ec.node.CreeateEDDSAResharingSession(walletID, false, readyPeerIDs, newThreshold, ec.resharingResultQueue)
			if err != nil {
				logger.Error("Failed to create resharing session", err)
				return
			}
		}

		oldPSession.Init()
		newPSession.Init()

		oldPSessionCtx, oldPSessionDone := context.WithCancel(context.Background())
		newPSessionCtx, newPSessionDone := context.WithCancel(context.Background())

		successEvent := &mpc.ResharingSuccessEvent{
			WalletID: walletID,
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// For old party, we just need to wait for completion
		go func() {
			for {
				select {
				case <-oldPSessionCtx.Done():
					wg.Done()
					logger.Info("oldPSession done")
					return
				case err := <-oldPSession.ErrChan():
					if err != nil {
						logger.Error("Resharing session error", err)
					}
				}
			}
		}()

		// For new party, we need to get the public key
		go func() {
			for {
				select {
				case <-newPSessionCtx.Done():
					if msg.KeyType == types.KeyTypeSecp256k1 {
						successEvent.ECDSAPubKey = newPSession.GetPubKeyResult()
					} else {
						successEvent.EDDSAPubKey = newPSession.GetPubKeyResult()
					}
					wg.Done()
					logger.Info("newPSession done")
					return
				case err := <-newPSession.ErrChan():
					if err != nil {
						logger.Error("Resharing session error", err)
					}
				}
			}
		}()

		// Start listening for messages
		oldPSession.ListenToIncomingResharingMessageAsync()
		newPSession.ListenToIncomingResharingMessageAsync()
		time.Sleep(1 * time.Second)

		// Start resharing process
		go oldPSession.Resharing(oldPSessionDone)
		go newPSession.Resharing(newPSessionDone)

		// Wait for both sessions to complete
		wg.Wait()
		logger.Info("Closing session successfully!",
			"event", successEvent)

		successEventBytes, err := json.Marshal(successEvent)
		if err != nil {
			logger.Error("Failed to marshal resharing success event", err)
			return
		}

		err = ec.resharingResultQueue.Enqueue(fmt.Sprintf(mpc.TypeResharingSuccess, walletID), successEventBytes, &messaging.EnqueueOptions{
			IdempotententKey: fmt.Sprintf(mpc.TypeResharingSuccess, walletID),
		})
		if err != nil {
			logger.Error("Failed to publish resharing result event", err)
			return
		}

		logger.Info("[COMPLETED RESHARING] Resharing completed successfully",
			"walletID", walletID)
	})

	ec.resharingSub = sub
	if err != nil {
		return err
	}
	return nil
}

// Add a cleanup routine that runs periodically
func (ec *eventConsumer) sessionCleanupRoutine() {
	ticker := time.NewTicker(ec.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ec.cleanupStaleSessions()
		case <-ec.cleanupStopChan:
			return
		}
	}
}

// Cleanup stale sessions
func (ec *eventConsumer) cleanupStaleSessions() {
	now := time.Now()
	ec.sessionsLock.Lock()
	defer ec.sessionsLock.Unlock()

	for sessionID, creationTime := range ec.activeSessions {
		if now.Sub(creationTime) > ec.sessionTimeout {
			logger.Info("Cleaning up stale session", "sessionID", sessionID, "age", now.Sub(creationTime))
			delete(ec.activeSessions, sessionID)
		}
	}
}

// markSessionAsActive marks a session as active with the current timestamp
func (ec *eventConsumer) addSession(walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)
	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// checkAndTrackSession checks if a session already exists and tracks it if new.
// Returns true if the session is a duplicate.
func (ec *eventConsumer) checkDuplicateSession(walletID, txID string) bool {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)

	// Check for duplicate
	ec.sessionsLock.RLock()
	_, isDuplicate := ec.activeSessions[sessionID]
	ec.sessionsLock.RUnlock()

	if isDuplicate {
		logger.Info("Duplicate signing request detected", "walletID", walletID, "txID", txID)
		return true
	}

	return false
}

// Close and clean up
func (ec *eventConsumer) Close() error {
	// Signal cleanup routine to stop
	close(ec.cleanupStopChan)

	err := ec.keyGenerationSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.signingSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}
