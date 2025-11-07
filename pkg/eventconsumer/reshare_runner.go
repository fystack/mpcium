package eventconsumer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/taurus"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

// NOTE: In Taurus reshare, it just refresh the keyshare of each node but keep the same public key and threshold.
// Therefore, we don't need to create new party sessions for CMP reshare.
func (ec *eventConsumer) handleTaurusReshare(msg types.ResharingMessage, natMsg *nats.Msg) {
	logger.Info(
		"Starting reshare",
		"walletID",
		msg.WalletID,
		"sessionID",
		msg.SessionID,
		"keyType",
		msg.KeyType,
	)

	// Create Taurus session for reshare
	session, err := ec.node.CreateTaurusSession(
		msg.WalletID,
		msg.NewThreshold,
		msg.Protocol,
		taurus.ActReshare,
	)
	if err != nil {
		logger.Error(
			"Failed to create reshare session",
			err,
			"walletID",
			msg.WalletID,
			"keyType",
			msg.KeyType,
		)
		ec.handleReshareSessionError(
			msg.WalletID,
			msg.KeyType,
			msg.NewThreshold,
			err,
			fmt.Sprintf("Failed to create %s reshare session", msg.KeyType),
			natMsg,
		)
		return
	}

	// Load the existing key for reshare
	if err := session.LoadKey(msg.WalletID); err != nil {
		logger.Error(
			"Failed to load key for reshare",
			err,
			"walletID",
			msg.WalletID,
			"keyType",
			msg.KeyType,
		)
		ec.handleReshareSessionError(
			msg.WalletID,
			msg.KeyType,
			msg.NewThreshold,
			err,
			fmt.Sprintf("Failed to load key for %s reshare", msg.KeyType),
			natMsg,
		)
		return
	}

	// Create context for reshare
	ctx, cancel := context.WithTimeout(
		context.Background(),
		60*time.Second,
	) // Longer timeout for reshare
	defer cancel()

	// Perform reshare
	keyData, err := session.Reshare(ctx)
	if err != nil {
		logger.Error(
			"Reshare failed",
			err,
			"walletID",
			msg.WalletID,
			"sessionID",
			msg.SessionID,
			"keyType",
			msg.KeyType,
		)
		ec.handleReshareSessionError(
			msg.WalletID,
			msg.KeyType,
			msg.NewThreshold,
			err,
			fmt.Sprintf("Reshare failed for %s", msg.KeyType),
			natMsg,
		)
		return
	}

	// Create reshare result event
	reshareResult := event.ResharingResultEvent{
		ResultType:   event.ResultTypeSuccess,
		WalletID:     msg.WalletID,
		NewThreshold: keyData.Threshold,
		KeyType:      msg.KeyType,
		PubKey:       keyData.PubKeyBytes,
	}

	// Marshal and enqueue the result
	reshareResultBytes, err := json.Marshal(reshareResult)
	if err != nil {
		logger.Error(
			"Failed to marshal reshare result event",
			err,
			"walletID",
			msg.WalletID,
			"sessionID",
			msg.SessionID,
			"keyType",
			msg.KeyType,
		)
		ec.handleReshareSessionError(
			msg.WalletID,
			msg.KeyType,
			msg.NewThreshold,
			err,
			fmt.Sprintf("Failed to marshal %s reshare result", msg.KeyType),
			natMsg,
		)
		return
	}

	// Enqueue the reshare result
	key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, msg.SessionID)
	err = ec.reshareResultQueue.Enqueue(key, reshareResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: composeReshareIdempotentKey(msg.SessionID, natMsg),
	})
	if err != nil {
		logger.Error(
			"Failed to enqueue reshare result event",
			err,
			"walletID",
			msg.WalletID,
			"sessionID",
			msg.SessionID,
			"keyType",
			msg.KeyType,
		)
		ec.handleReshareSessionError(
			msg.WalletID,
			msg.KeyType,
			msg.NewThreshold,
			err,
			fmt.Sprintf("Failed to enqueue %s reshare result", msg.KeyType),
			natMsg,
		)
		return
	}

	// Remove this line - don't send reply for reshare messages
	// ec.sendReplyToRemoveMsg(natMsg)

	logger.Info(
		"[COMPLETED RESHARE] CMP reshare completed successfully",
		"walletID",
		msg.WalletID,
		"sessionID",
		msg.SessionID,
	)
}

// runClassicReshare handles non-Taurus reshare flows (ECDSA/EDDSA)
func (ec *eventConsumer) runClassicReshare(
	msg types.ResharingMessage,
	natMsg *nats.Msg,
	sessionType mpc.SessionType,
) {
	walletID := msg.WalletID
	keyType := msg.KeyType

	createSession := func(isNewPeer bool) (mpc.ReshareSession, error) {
		return ec.node.CreateReshareSession(
			sessionType,
			walletID,
			msg.NewThreshold,
			msg.NodeIDs,
			isNewPeer,
			ec.reshareResultQueue,
		)
	}

	oldSession, err := createSession(false)
	if err != nil {
		logger.Error("Failed to create old reshare session", err, "walletID", walletID)
		ec.handleReshareSessionError(
			walletID,
			keyType,
			msg.NewThreshold,
			err,
			"Failed to create old reshare session",
			natMsg,
		)
		return
	}
	newSession, err := createSession(true)
	if err != nil {
		logger.Error("Failed to create new reshare session", err, "walletID", walletID)
		ec.handleReshareSessionError(
			walletID,
			keyType,
			msg.NewThreshold,
			err,
			"Failed to create new reshare session",
			natMsg,
		)
		return
	}

	if oldSession == nil && newSession == nil {
		logger.Info(
			"Node is not participating in this reshare (neither old nor new)",
			"walletID",
			walletID,
		)
		return
	}

	ctx := context.Background()
	var wg sync.WaitGroup

	successEvent := &event.ResharingResultEvent{
		WalletID:     walletID,
		NewThreshold: msg.NewThreshold,
		KeyType:      msg.KeyType,
		ResultType:   event.ResultTypeSuccess,
	}

	if oldSession != nil {
		err := oldSession.Init()
		if err != nil {
			ec.handleReshareSessionError(
				walletID,
				keyType,
				msg.NewThreshold,
				err,
				"Failed to init old reshare session",
				natMsg,
			)
			return
		}
		oldSession.ListenToIncomingMessageAsync()
	}

	if newSession != nil {
		err := newSession.Init()
		if err != nil {
			ec.handleReshareSessionError(
				walletID,
				keyType,
				msg.NewThreshold,
				err,
				"Failed to init new reshare session",
				natMsg,
			)
			return
		}
		newSession.ListenToIncomingMessageAsync()
		// In resharing process, we need to ensure that the new session is aware of the old committee peers.
		// Then new committee peers can start listening to the old committee peers
		// and thus enable receiving direct messages from them.
		extraOldCommiteePeers := newSession.GetLegacyCommitteePeers()
		newSession.ListenToPeersAsync(extraOldCommiteePeers)
	}

	ec.warmUpSession()
	if oldSession != nil {
		ctxOld, doneOld := context.WithCancel(ctx)
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
					ec.handleReshareSessionError(
						walletID,
						keyType,
						msg.NewThreshold,
						err,
						"Old reshare session error",
						natMsg,
					)
					doneOld()
					return
				}
			}
		}()
	}

	if newSession != nil {
		ctxNew, doneNew := context.WithCancel(ctx)
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
					ec.handleReshareSessionError(
						walletID,
						keyType,
						msg.NewThreshold,
						err,
						"New reshare session error",
						natMsg,
					)
					doneNew()
					return
				}
			}
		}()
	}

	wg.Wait()
	logger.Info(
		"Reshare session finished",
		"walletID",
		walletID,
		"pubKey",
		fmt.Sprintf("%x", successEvent.PubKey),
	)

	if newSession != nil {
		successBytes, err := json.Marshal(successEvent)
		if err != nil {
			logger.Error("Failed to marshal reshare success event", err)
			ec.handleReshareSessionError(
				walletID,
				keyType,
				msg.NewThreshold,
				err,
				"Failed to marshal reshare success event",
				natMsg,
			)
			return
		}

		key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, msg.SessionID)
		err = ec.reshareResultQueue.Enqueue(
			key,
			successBytes,
			&messaging.EnqueueOptions{
				IdempotententKey: composeReshareIdempotentKey(msg.SessionID, natMsg),
			})
		if err != nil {
			logger.Error("Failed to publish reshare success message", err)
			ec.handleReshareSessionError(
				walletID,
				keyType,
				msg.NewThreshold,
				err,
				"Failed to publish reshare success message",
				natMsg,
			)
			return
		}
		logger.Info("[COMPLETED RESHARE] Successfully published", "walletID", walletID)
	} else {
		logger.Info("[COMPLETED RESHARE] Done (not a new party)", "walletID", walletID)
	}
}
