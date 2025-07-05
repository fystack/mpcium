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
	MPCGenerateEvent = "mpc:generate"
	MPCSignEvent     = "mpc:sign"
	MPCReshareEvent  = "mpc:reshare"

	DefaultConcurrentKeygen    = 2
	DefaultSessionStartupDelay = 500

	KeyGenTimeOut = 30 * time.Second
)

type EventConsumer interface {
	Run()
	Close() error
}

type eventConsumer struct {
	node         *mpc.Node
	pubsub       messaging.PubSub
	mpcThreshold int

	genKeyResultQueue  messaging.MessageQueue
	signingResultQueue messaging.MessageQueue
	reshareResultQueue messaging.MessageQueue

	keyGenerationSub messaging.Subscription
	signingSub       messaging.Subscription
	reshareSub       messaging.Subscription
	identityStore    identity.Store

	msgBuffer           chan *nats.Msg
	maxConcurrentKeygen int

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
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	reshareResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	maxConcurrentKeygen := viper.GetInt("max_concurrent_keygen")
	if maxConcurrentKeygen == 0 {
		maxConcurrentKeygen = DefaultConcurrentKeygen
	}

	ec := &eventConsumer{
		node:                node,
		pubsub:              pubsub,
		genKeyResultQueue:   genKeyResultQueue,
		signingResultQueue:  signingResultQueue,
		reshareResultQueue:  reshareResultQueue,
		activeSessions:      make(map[string]time.Time),
		cleanupInterval:     5 * time.Minute,  // Run cleanup every 5 minutes
		sessionTimeout:      30 * time.Minute, // Consider sessions older than 30 minutes stale
		cleanupStopChan:     make(chan struct{}),
		mpcThreshold:        viper.GetInt("mpc_threshold"),
		maxConcurrentKeygen: maxConcurrentKeygen,
		identityStore:       identityStore,
		msgBuffer:           make(chan *nats.Msg, 100),
	}

	go ec.startKeyGenEventWorker()
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

	err = ec.consumeReshareEvent()
	if err != nil {
		log.Fatal("Failed to consume reshare event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

func (ec *eventConsumer) handleKeyGenEvent(natMsg *nats.Msg) {
	baseCtx, baseCancel := context.WithTimeout(context.Background(), KeyGenTimeOut)
	defer baseCancel()

	raw := natMsg.Data
	var msg types.GenerateKeyMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		logger.Error("Failed to unmarshal keygen message", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to unmarshal keygen message", natMsg)
		return
	}
	if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
		logger.Error("Failed to verify initiator message", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to verify initiator message", natMsg)
		return
	}

	walletID := msg.WalletID
	ecdsaSession, err := ec.node.CreateKeyGenSession(mpc.SessionTypeECDSA, walletID, ec.mpcThreshold, ec.genKeyResultQueue)
	if err != nil {
		logger.Error("Failed to create ECDSA key generation session", err, "walletID", walletID)
		ec.handleKeygenSessionError(walletID, err, "Failed to create ECDSA key generation session", natMsg)
		return
	}
	eddsaSession, err := ec.node.CreateKeyGenSession(mpc.SessionTypeEDDSA, walletID, ec.mpcThreshold, ec.genKeyResultQueue)
	if err != nil {
		logger.Error("Failed to create EdDSA key generation session", err, "walletID", walletID)
		ec.handleKeygenSessionError(walletID, err, "Failed to create EdDSA key generation session", natMsg)
		return
	}
	ecdsaSession.Init()
	eddsaSession.Init()

	ctxEcdsa, doneEcdsa := context.WithCancel(baseCtx)
	ctxEddsa, doneEddsa := context.WithCancel(baseCtx)

	successEvent := &event.KeygenResultEvent{WalletID: walletID, ResultType: event.ResultTypeSuccess}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		select {
		case <-ctxEcdsa.Done():
			successEvent.ECDSAPubKey = ecdsaSession.GetPubKeyResult()
		case err := <-ecdsaSession.ErrChan():
			logger.Error("ECDSA keygen session error", err)
			ec.handleKeygenSessionError(walletID, err, "ECDSA keygen session error", natMsg)
			doneEcdsa()
		}
	}()
	go func() {
		defer wg.Done()
		select {
		case <-ctxEddsa.Done():
			successEvent.EDDSAPubKey = eddsaSession.GetPubKeyResult()
		case err := <-eddsaSession.ErrChan():
			logger.Error("EdDSA keygen session error", err)
			ec.handleKeygenSessionError(walletID, err, "EdDSA keygen session error", natMsg)
			doneEddsa()
		}
	}()

	ecdsaSession.ListenToIncomingMessageAsync()
	eddsaSession.ListenToIncomingMessageAsync()

	// Temporary delay for peer setup
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)
	go ecdsaSession.GenerateKey(doneEcdsa)
	go eddsaSession.GenerateKey(doneEddsa)

	// Wait for completion or timeout
	doneAll := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneAll)
	}()

	select {
	case <-doneAll:
		// all sessions finished before timeout
	case <-baseCtx.Done():
		// timeout occurred
		logger.Warn("Key generation timed out", "walletID", walletID)
		ec.handleKeygenSessionError(walletID, fmt.Errorf("keygen session timed out after"), "Key generation timed out", natMsg)
		return
	}

	logger.Info("Closing session successfully!", "event", successEvent)
	payload, err := json.Marshal(successEvent)
	if err != nil {
		logger.Error("Failed to marshal keygen success event", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to marshal keygen success event", natMsg)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	if err := ec.genKeyResultQueue.Enqueue(key, payload, &messaging.EnqueueOptions{IdempotententKey: key}); err != nil {
		logger.Error("Failed to publish key generation success message", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to publish key generation success message", natMsg)
		return
	}
	ec.sendReplyToRemoveMsg(natMsg)
	logger.Info("[COMPLETED KEY GEN] Key generation completed successfully", "walletID", walletID)
}

// handleKeygenSessionError handles errors that occur during key generation
func (ec *eventConsumer) handleKeygenSessionError(walletID string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Keygen session error",
		"walletID", walletID,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	keygenResult := event.KeygenResultEvent{
		ResultType:  event.ResultTypeError,
		ErrorCode:   string(errorCode),
		WalletID:    walletID,
		ErrorReason: fullErrMsg,
	}

	keygenResultBytes, err := json.Marshal(keygenResult)
	if err != nil {
		logger.Error("Failed to marshal keygen result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	err = ec.genKeyResultQueue.Enqueue(key, keygenResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: key,
	})
	if err != nil {
		logger.Error("Failed to enqueue keygen result event", err,
			"walletID", walletID,
			"payload", string(keygenResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) startKeyGenEventWorker() {
	// semaphore to limit concurrency
	semaphore := make(chan struct{}, ec.maxConcurrentKeygen)

	for natMsg := range ec.msgBuffer {
		semaphore <- struct{}{} // acquire a slot
		go func(msg *nats.Msg) {
			defer func() { <-semaphore }() // release the slot when done
			ec.handleKeyGenEvent(msg)
		}(natMsg)
	}
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		ec.msgBuffer <- natMsg
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
			return
		}

		var session mpc.SigningSession
		switch msg.KeyType {
		case types.KeyTypeSecp256k1:
			session, err = ec.node.CreateSigningSession(
				mpc.SessionTypeECDSA,
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				ec.signingResultQueue,
			)
		case types.KeyTypeEd25519:
			session, err = ec.node.CreateSigningSession(
				mpc.SessionTypeEDDSA,
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				ec.signingResultQueue,
			)

		}
		if err != nil {
			logger.Error("Failed to create signing session", err)
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
		time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

		onSuccess := func(data []byte) {
			done()
			ec.sendReplyToRemoveMsg(natMsg)
		}
		go session.Sign(onSuccess)
	})

	ec.signingSub = sub
	if err != nil {
		return err
	}

	return nil
}
func (ec *eventConsumer) handleSigningSessionError(walletID, txID, networkInternalCode string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Signing session error",
		"walletID", walletID,
		"txID", txID,
		"networkInternalCode", networkInternalCode,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	signingResult := event.SigningResultEvent{
		ResultType:          event.ResultTypeError,
		ErrorCode:           errorCode,
		NetworkInternalCode: networkInternalCode,
		WalletID:            walletID,
		TxID:                txID,
		ErrorReason:         fullErrMsg,
	}

	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error("Failed to marshal signing result event", err,
			"walletID", walletID,
			"txID", txID,
		)
		return
	}
	err = ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signingResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: txID,
	})
	if err != nil {
		logger.Error("Failed to enqueue signing result event", err,
			"walletID", walletID,
			"txID", txID,
			"payload", string(signingResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) sendReplyToRemoveMsg(natMsg *nats.Msg) {
	msg := natMsg.Data

	if natMsg.Reply == "" {
		logger.Warn("No reply inbox specified for sign success message", "msg", string(msg))
		return
	}

	err := ec.pubsub.Publish(natMsg.Reply, msg)
	if err != nil {
		logger.Error("Failed to reply message", err, "reply", natMsg.Reply)
		return
	}
}

func (ec *eventConsumer) consumeReshareEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCReshareEvent, func(natMsg *nats.Msg) {
		var msg types.ResharingMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal resharing message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to unmarshal resharing message")
			return
		}

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to verify initiator message")
			return
		}

		walletID := msg.WalletID
		keyType := msg.KeyType

		sessionType, err := sessionTypeFromKeyType(keyType)
		if err != nil {
			logger.Error("Failed to get session type", err)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to get session type")
			return
		}

		createSession := func(isNewPeer bool) (mpc.ReshareSession, error) {
			return ec.node.CreateReshareSession(
				sessionType,
				walletID,
				ec.mpcThreshold,
				msg.NewThreshold,
				msg.NodeIDs,
				isNewPeer,
				ec.reshareResultQueue,
			)
		}

		oldSession, err := createSession(false)
		if err != nil {
			logger.Error("Failed to create old reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create old reshare session")
			return
		}
		newSession, err := createSession(true)
		if err != nil {
			logger.Error("Failed to create new reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create new reshare session")
			return
		}

		if oldSession == nil && newSession == nil {
			logger.Info("Node is not participating in this reshare (neither old nor new)", "walletID", walletID)
			return
		}

		successEvent := &event.ResharingResultEvent{
			WalletID:     walletID,
			NewThreshold: msg.NewThreshold,
			KeyType:      msg.KeyType,
			ResultType:   event.ResultTypeSuccess,
		}

		var wg sync.WaitGroup
		ctx := context.Background()

		time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

		if oldSession != nil {
			ctxOld, doneOld := context.WithCancel(ctx)
			oldSession.Init()
			oldSession.ListenToIncomingMessageAsync()
			go oldSession.Reshare(doneOld)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxOld.Done():
						return
					case err := <-oldSession.ErrChan():
						logger.Error("Old reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Old reshare session error")
						doneOld() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		if newSession != nil {
			ctxNew, doneNew := context.WithCancel(ctx)
			newSession.Init()
			newSession.ListenToIncomingMessageAsync()
			go newSession.Reshare(doneNew)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxNew.Done():
						successEvent.PubKey = newSession.GetPubKeyResult()
						return
					case err := <-newSession.ErrChan():
						logger.Error("New reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "New reshare session error")
						doneNew() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		wg.Wait()

		logger.Info("Reshare session finished", "walletID", walletID, "pubKey", fmt.Sprintf("%x", successEvent.PubKey))

		if newSession != nil {
			successBytes, err := json.Marshal(successEvent)
			if err != nil {
				logger.Error("Failed to marshal reshare success event", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to marshal reshare success event")
				return
			}

			key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, walletID)
			err = ec.reshareResultQueue.Enqueue(
				key,
				successBytes,
				&messaging.EnqueueOptions{
					IdempotententKey: key,
				})
			if err != nil {
				logger.Error("Failed to publish reshare success message", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to publish reshare success message")
				return
			}
			logger.Info("[COMPLETED RESHARE] Successfully published", "walletID", walletID)
		} else {
			logger.Info("[COMPLETED RESHARE] Done (not a new party)", "walletID", walletID)
		}
	})

	ec.reshareSub = sub
	return err
}

// handleReshareSessionError handles errors that occur during reshare operations
func (ec *eventConsumer) handleReshareSessionError(walletID string, keyType types.KeyType, newThreshold int, err error, contextMsg string) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Reshare session error",
		"walletID", walletID,
		"keyType", keyType,
		"newThreshold", newThreshold,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	reshareResult := event.ResharingResultEvent{
		ResultType:   event.ResultTypeError,
		ErrorCode:    string(errorCode),
		WalletID:     walletID,
		KeyType:      keyType,
		NewThreshold: newThreshold,
		ErrorReason:  fullErrMsg,
	}

	reshareResultBytes, err := json.Marshal(reshareResult)
	if err != nil {
		logger.Error("Failed to marshal reshare result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, walletID)
	err = ec.reshareResultQueue.Enqueue(key, reshareResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: key,
	})
	if err != nil {
		logger.Error("Failed to enqueue reshare result event", err,
			"walletID", walletID,
			"payload", string(reshareResultBytes),
		)
	}
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

// Remove a session from tracking
func (ec *eventConsumer) removeSession(walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)
	ec.sessionsLock.Lock()
	delete(ec.activeSessions, sessionID)
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
	err = ec.reshareSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}

func sessionTypeFromKeyType(keyType types.KeyType) (mpc.SessionType, error) {
	switch keyType {
	case types.KeyTypeSecp256k1:
		return mpc.SessionTypeECDSA, nil
	case types.KeyTypeEd25519:
		return mpc.SessionTypeEDDSA, nil
	default:
		logger.Warn("Unsupported key type", "keyType", keyType)
		return "", fmt.Errorf("unsupported key type: %v", keyType)
	}
}
