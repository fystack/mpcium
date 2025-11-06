package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/taurus"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

const (
	MPCGenerateEvent = "mpc:generate"
	MPCSignEvent     = "mpc:sign"
	MPCReshareEvent  = "mpc:reshare"
	MPCPresignEvent  = "mpc:presign"

	// Internal event to notify presign pool of a hot wallet
	MPCHotWalletEvent = "mpc:wallet_hot"

	DefaultConcurrentKeygen   = 2
	DefaultConcurrentSigning  = 20
	DefaultSessionWarmUpDelay = 200

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
	presignResultQueue messaging.MessageQueue

	keyGenerationSub messaging.Subscription
	signingSub       messaging.Subscription
	reshareSub       messaging.Subscription
	presignSub       messaging.Subscription
	identityStore    identity.Store

	keygenMsgBuffer      chan *nats.Msg
	signingMsgBuffer     chan *nats.Msg
	maxConcurrentKeygen  int
	maxConcurrentSigning int
	sessionWarmUpDelayMs int

	// Track active sessions with timestamps for cleanup
	activeSessions  map[string]time.Time // Maps "walletID-txID" to creation time
	sessionsLock    sync.RWMutex
	cleanupInterval time.Duration // How often to run cleanup
	sessionTimeout  time.Duration // How long before a session is considered stale
	cleanupStopChan chan struct{} // Signal to stop cleanup goroutine

	// Track recent signing activity to detect hot wallets
	hotMu        sync.Mutex
	recentSigns  map[string][]time.Time // key: walletID|keyType|protocol → timestamps within window
	hotWindow    time.Duration          // window for counting signs (e.g., 5 minutes)
	hotThreshold int                    // signs needed to mark as hot
}

func NewEventConsumer(
	node *mpc.Node,
	pubsub messaging.PubSub,
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	reshareResultQueue messaging.MessageQueue,
	presignResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	maxConcurrentKeygen := viper.GetInt("max_concurrent_keygen")
	if maxConcurrentKeygen == 0 {
		maxConcurrentKeygen = DefaultConcurrentKeygen
	}

	maxConcurrentSigning := viper.GetInt("max_concurrent_signing")
	if maxConcurrentSigning == 0 {
		maxConcurrentSigning = DefaultConcurrentSigning
	}

	sessionWarmUpDelayMs := viper.GetInt("session_warm_up_delay_ms")
	if sessionWarmUpDelayMs == 0 {
		sessionWarmUpDelayMs = DefaultSessionWarmUpDelay
	}

	logger.Info(
		"Initializing event consumer",
		"max_concurrent_keygen",
		maxConcurrentKeygen,
		"max_concurrent_signing",
		maxConcurrentSigning,
		"session_warm_up_delay_ms",
		sessionWarmUpDelayMs,
	)

	ec := &eventConsumer{
		node:                 node,
		pubsub:               pubsub,
		genKeyResultQueue:    genKeyResultQueue,
		signingResultQueue:   signingResultQueue,
		reshareResultQueue:   reshareResultQueue,
		presignResultQueue:   presignResultQueue,
		activeSessions:       make(map[string]time.Time),
		cleanupInterval:      5 * time.Minute,  // Run cleanup every 5 minutes
		sessionTimeout:       30 * time.Minute, // Consider sessions older than 30 minutes stale
		cleanupStopChan:      make(chan struct{}),
		mpcThreshold:         viper.GetInt("mpc_threshold"),
		maxConcurrentKeygen:  maxConcurrentKeygen,
		maxConcurrentSigning: maxConcurrentSigning,
		identityStore:        identityStore,
		keygenMsgBuffer:      make(chan *nats.Msg, 100),
		signingMsgBuffer:     make(chan *nats.Msg, 200), // Larger buffer for signing
		sessionWarmUpDelayMs: sessionWarmUpDelayMs,
		recentSigns:          make(map[string][]time.Time),
		hotWindow:            5 * time.Minute,
		hotThreshold:         2,
	}

	go ec.startKeyGenEventWorker()
	go ec.startSigningEventWorker()
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

	err = ec.consumePresignEvent()
	if err != nil {
		log.Fatal("Failed to consume presign event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

func (ec *eventConsumer) warmUpSession() {
	time.Sleep(time.Duration(ec.sessionWarmUpDelayMs) * time.Millisecond)
}

func (ec *eventConsumer) handleKeyGenEvent(natMsg *nats.Msg) {
	baseCtx, baseCancel := context.WithTimeout(context.Background(), KeyGenTimeOut)
	defer baseCancel()

	var msg types.GenerateKeyMessage
	if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to unmarshal keygen message", natMsg)
		return
	}
	if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to verify initiator message", natMsg)
		return
	}

	if err := types.ValidateKeyProtocol(types.KeyTypeSecp256k1, msg.ECDSAProtocol); err != nil {
		ec.handleKeygenSessionError(msg.WalletID, err, "Invalid ECDSA protocol", natMsg)
		return
	}

	if err := types.ValidateKeyProtocol(types.KeyTypeEd25519, msg.EdDSAProtocol); err != nil {
		ec.handleKeygenSessionError(msg.WalletID, err, "Invalid EdDSA protocol", natMsg)
		return
	}

	walletID := msg.WalletID
	logger.Info(
		"[KEYGEN START]",
		"walletID",
		walletID,
		"ecdsa_protocol",
		msg.ECDSAProtocol,
		"eddsa_protocol",
		msg.EdDSAProtocol,
	)

	ctx, cancelAll := context.WithCancel(baseCtx)
	defer cancelAll()

	successEvent := &event.KeygenResultEvent{
		WalletID:    walletID,
		ResultType:  event.ResultTypeSuccess,
		ECDSAPubKey: nil,
		EDDSAPubKey: nil,
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(2)

	// run ECDSA keygen
	go func() {
		defer wg.Done()
		pub, err := ec.runECDSAKeygen(ctx, walletID, msg.ECDSAProtocol, natMsg)
		if err != nil {
			errCh <- err
			cancelAll()
			return
		}
		successEvent.ECDSAPubKey = pub
	}()

	// run EdDSA keygen
	go func() {
		defer wg.Done()
		pub, err := ec.runEdDSAKeygen(ctx, walletID, msg.EdDSAProtocol, natMsg)
		if err != nil {
			errCh <- err
			cancelAll()
			return
		}
		successEvent.EDDSAPubKey = pub
	}()

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		close(errCh)
		for err := range errCh {
			if err != nil {
				return
			}
		}
	case err := <-errCh:
		cancelAll()
		if err != nil {
			logger.Error("keygen failed", err, "walletID", walletID)
		}
		return
	case <-baseCtx.Done():
		cancelAll()
		ec.handleKeygenSessionError(
			walletID,
			fmt.Errorf("keygen timeout after %v", KeyGenTimeOut),
			"Keygen timeout",
			natMsg,
		)
		return
	}

	payload, err := json.Marshal(successEvent)
	if err != nil {
		logger.Error("Failed to marshal keygen success event", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to marshal keygen success event", natMsg)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	if err := ec.genKeyResultQueue.Enqueue(
		key,
		payload,
		&messaging.EnqueueOptions{IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg)},
	); err != nil {
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
		IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg),
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

	for natMsg := range ec.keygenMsgBuffer {
		semaphore <- struct{}{} // acquire a slot
		go func(msg *nats.Msg) {
			defer func() { <-semaphore }() // release the slot when done
			ec.handleKeyGenEvent(msg)
		}(natMsg)
	}
}

func (ec *eventConsumer) startSigningEventWorker() {
	// semaphore to limit concurrency
	semaphore := make(chan struct{}, ec.maxConcurrentSigning)

	for natMsg := range ec.signingMsgBuffer {
		semaphore <- struct{}{} // acquire a slot
		go func(msg *nats.Msg) {
			defer func() { <-semaphore }() // release the slot when done
			ec.handleSigningEvent(msg)
		}(natMsg)
	}
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		ec.keygenMsgBuffer <- natMsg
	})

	ec.keyGenerationSub = sub
	if err != nil {
		return err
	}
	return nil
}

func (ec *eventConsumer) handleSigningEvent(natMsg *nats.Msg) {
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

	if verr := types.ValidateKeyProtocol(msg.KeyType, msg.Protocol); verr != nil {
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			verr,
			verr.Error(),
			natMsg,
		)
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

	// Track activity to detect hot wallets
	ec.trackAndMaybeNotifyHot(msg)

	// Check for duplicate session and track if new
	if ec.checkDuplicateSession(msg.WalletID, msg.TxID) {
		duplicateErr := fmt.Errorf(
			"duplicate signing request detected for walletID=%s txID=%s",
			msg.WalletID,
			msg.TxID,
		)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			duplicateErr,
			"Duplicate session",
			natMsg,
		)
		return
	}

	// Route Taurus signing by algorithm (matches keygen behavior)
	if msg.Protocol == types.ProtocolCGGMP21 || msg.Protocol == types.ProtocolTaproot ||
		msg.Protocol == types.ProtocolFROST {
		ec.handleTaurusSigning(msg.Protocol, msg, natMsg)
		return
	}

	// Classic signing (ECDSA/EDDSA)
	ec.runClassicSigning(msg, natMsg)
}

func (ec *eventConsumer) consumeTxSigningEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCSignEvent, func(natMsg *nats.Msg) {
		ec.signingMsgBuffer <- natMsg // Send to worker instead of processing directly
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
		IdempotententKey: composeSigningIdempotentKey(txID, natMsg),
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
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to unmarshal resharing message", natMsg)
			return
		}

		if msg.SessionID == "" {
			ec.handleReshareSessionError(
				msg.WalletID,
				msg.KeyType,
				msg.NewThreshold,
				errors.New("validation: session ID is empty"),
				"Session ID is empty",
				natMsg,
			)
			return
		}

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			ec.handleReshareSessionError(
				msg.WalletID,
				msg.KeyType,
				msg.NewThreshold,
				err,
				"Failed to verify initiator message",
				natMsg,
			)
			return
		}
		if verr := types.ValidateKeyProtocol(msg.KeyType, msg.Protocol); verr != nil {
			ec.handleReshareSessionError(
				msg.WalletID,
				msg.KeyType,
				msg.NewThreshold,
				verr,
				verr.Error(),
				natMsg,
			)
			return
		}

		walletID := msg.WalletID
		keyType := msg.KeyType

		sessionType, err := sessionTypeFromKeyType(keyType)
		if err != nil {
			logger.Error("Failed to get session type", err)
			ec.handleReshareSessionError(
				walletID,
				keyType,
				msg.NewThreshold,
				err,
				"Failed to get session type",
				natMsg,
			)
			return
		}
		// Handle CMP reshare separately by algorithm
		if msg.Protocol == types.ProtocolCGGMP21 || msg.Protocol == types.ProtocolTaproot ||
			msg.Protocol == types.ProtocolFROST {
			ec.handleTaurusReshare(msg, natMsg)
			return
		}

		ec.runClassicReshare(msg, natMsg, sessionType)
	})
	ec.reshareSub = sub
	return err
}

// handleReshareSessionError handles errors that occur during reshare operations
func (ec *eventConsumer) handleReshareSessionError(
	walletID string,
	keyType types.KeyType,
	newThreshold int,
	err error,
	contextMsg string,
	natMsg *nats.Msg,
) {
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
		IdempotententKey: composeReshareIdempotentKey(walletID, natMsg),
	})
	if err != nil {
		logger.Error("Failed to enqueue reshare result event", err,
			"walletID", walletID,
			"payload", string(reshareResultBytes),
		)
	}
}

func (ec *eventConsumer) consumePresignEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCPresignEvent, func(natMsg *nats.Msg) {
		var msg types.PresignTxMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal presign message", err)
			return
		}
		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		// Only CGGMP21 supports presign
		if msg.Protocol != types.ProtocolCGGMP21 {
			ec.handlePresignSessionError(msg.WalletID,
				fmt.Errorf("presign is only supported for CGGMP21 key type"),
				"Unsupported key type for presign",
				natMsg,
			)
			return
		}
		session, err := ec.node.CreateTaurusSession(msg.WalletID, ec.mpcThreshold, msg.Protocol, taurus.ActPresign)
		if err != nil {
			ec.handlePresignSessionError(msg.WalletID,
				err, "Failed to create presign session",
				natMsg,
			)
			return
		}

		ctx := context.Background()
		success, err := session.Presign(ctx, msg.WalletID)
		if err != nil {
			ec.handlePresignSessionError(msg.WalletID,
				err, "Presign operation failed",
				natMsg,
			)
			return
		}

		if success {
			ec.handlePresignSessionSuccess(msg.WalletID, msg.TxID, natMsg)
		} else {
			ec.handlePresignSessionError(msg.WalletID,
				fmt.Errorf("presign operation returned false"),
				"Presign operation failed",
				natMsg,
			)
		}
	})
	if err != nil {
		return err
	}

	ec.presignSub = sub
	return nil
}

// handlePresignSessionSuccess handles successful presign operations
func (ec *eventConsumer) handlePresignSessionSuccess(walletID string, txID string, natMsg *nats.Msg) {
	presignResult := event.PresignResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   walletID,
		TxID:       txID,
		Status:     "success",
	}

	presignResultBytes, err := json.Marshal(presignResult)
	if err != nil {
		logger.Error("Failed to marshal presign result event", err,
			"walletID", walletID,
		)
		return
	}

	err = ec.presignResultQueue.Enqueue(event.PresignResultTopic, presignResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: composePresignIdempotentKey(walletID, natMsg),
	})
	if err != nil {
		logger.Error("Failed to enqueue presign result event", err,
			"walletID", walletID,
			"payload", string(presignResultBytes),
		)
	}
	// Presign events don't use reply inboxes, so no need to send reply
	logger.Info("[COMPLETED PRESIGN] Presign completed successfully", "walletID", walletID)
}

// handlePresignSessionError handles errors that occur during presign operations
func (ec *eventConsumer) handlePresignSessionError(walletID string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Presign session error",
		"walletID", walletID,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	presignResult := event.PresignResultEvent{
		ResultType:  event.ResultTypeError,
		ErrorCode:   errorCode,
		WalletID:    walletID,
		ErrorReason: fullErrMsg,
		Status:      "failed",
	}

	presignResultBytes, err := json.Marshal(presignResult)
	if err != nil {
		logger.Error("Failed to marshal presign result event", err,
			"walletID", walletID,
		)
		return
	}

	err = ec.presignResultQueue.Enqueue(event.PresignResultTopic, presignResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: composePresignIdempotentKey(walletID, natMsg),
	})
	if err != nil {
		logger.Error("Failed to enqueue presign result event", err,
			"walletID", walletID,
			"payload", string(presignResultBytes),
		)
	}
	// Presign events don't use reply inboxes, so no need to send reply
}

// composePresignIdempotentKey creates an idempotent key for presign operations
func composePresignIdempotentKey(walletID string, natMsg *nats.Msg) string {
	return fmt.Sprintf("presign:%s:%s", walletID, natMsg.Header.Get("Nats-Msg-Id"))
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

	// Close message buffers to stop workers
	close(ec.keygenMsgBuffer)
	close(ec.signingMsgBuffer)

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

// composeIdempotentKey creates an idempotent key for different MPC operation types
func composeIdempotentKey(baseID string, natMsg *nats.Msg, formatTemplate string) string {
	var uniqueKey string
	sid := natMsg.Header.Get("SessionID")
	if sid != "" {
		uniqueKey = fmt.Sprintf("%s:%s", baseID, sid)
	} else {
		uniqueKey = baseID
	}
	return fmt.Sprintf(formatTemplate, uniqueKey)
}

func composeKeygenIdempotentKey(walletID string, natMsg *nats.Msg) string {
	return composeIdempotentKey(walletID, natMsg, mpc.TypeGenerateWalletResultFmt)
}

func composeSigningIdempotentKey(txID string, natMsg *nats.Msg) string {
	return composeIdempotentKey(txID, natMsg, mpc.TypeSigningResultFmt)
}

func composeReshareIdempotentKey(sessionID string, natMsg *nats.Msg) string {
	return composeIdempotentKey(sessionID, natMsg, mpc.TypeReshareWalletResultFmt)
}

// trackAndMaybeNotifyHot records a signing event and publishes a hot wallet event
// if at least hotThreshold signs occur within hotWindow for the same
// (walletID, keyType, protocol) tuple.
func (ec *eventConsumer) trackAndMaybeNotifyHot(msg types.SignTxMessage) {
	if msg.Protocol != types.ProtocolCGGMP21 {
		return
	}
	key := fmt.Sprintf("%s:%s:%s", msg.WalletID, string(msg.KeyType), string(msg.Protocol))
	now := time.Now()

	ec.hotMu.Lock()
	// prune old entries
	list := ec.recentSigns[key]
	pruned := list[:0]
	cutoff := now.Add(-ec.hotWindow)
	for _, t := range list {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}

	ec.recentSigns[key] = append([]time.Time(nil), pruned...)
	currentCount := len(ec.recentSigns[key])

	// If this push reaches the threshold, publish hot wallet once
	shouldPublish := currentCount+1 == ec.hotThreshold
	ec.recentSigns[key] = append(ec.recentSigns[key], now)
	ec.hotMu.Unlock()

	if shouldPublish {
		_ = ec.pubsub.Publish(MPCHotWalletEvent, []byte(msg.WalletID))
		logger.Info("Published hot wallet event", "walletID", msg.WalletID)
	}
}
