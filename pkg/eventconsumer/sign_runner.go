package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/taurus"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

func (ec *eventConsumer) handleTaurusSigning(
	algorithm types.Protocol,
	msg types.SignTxMessage,
	natMsg *nats.Msg,
) {
	logger.Info(
		"Starting signing",
		"walletID",
		msg.WalletID,
		"txID",
		msg.TxID,
		"algorithm",
		algorithm,
	)
	session, err := ec.node.CreateTaurusSession(
		msg.WalletID,
		ec.mpcThreshold,
		algorithm,
		taurus.ActSign,
	)
	if err != nil {
		logger.Error("Failed to create session", err, "walletID", msg.WalletID)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			fmt.Sprintf("Failed to create %s session: %v", algorithm, err),
			natMsg,
		)
		return
	}

	// Convert transaction bytes to big.Int
	txBigInt := new(big.Int).SetBytes(msg.Tx)

	// Create context for signing
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	signature, err := session.Sign(ctx, txBigInt)
	if err != nil {
		logger.Error(
			"signing failed",
			err,
			"algorithm",
			algorithm,
			"walletID",
			msg.WalletID,
			"txID",
			msg.TxID,
		)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			fmt.Sprintf("%s signing failed", algorithm),
			natMsg,
		)
		return
	}

	// Create signing result event
	signingResult := event.SigningResultEvent{
		ResultType:          event.ResultTypeSuccess,
		NetworkInternalCode: msg.NetworkInternalCode,
		WalletID:            msg.WalletID,
		TxID:                msg.TxID,
		Signature:           signature, // Returns the full signature
	}

	// Marshal and enqueue the result
	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error(
			"Failed to marshal signing result event",
			err,
			"algorithm",
			algorithm,
			"walletID",
			msg.WalletID,
			"txID",
			msg.TxID,
		)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			fmt.Sprintf("Failed to marshal %s signing result", algorithm),
			natMsg,
		)
		return
	}

	// Enqueue the signing result
	err = ec.signingResultQueue.Enqueue(
		event.SigningResultCompleteTopic,
		signingResultBytes,
		&messaging.EnqueueOptions{
			IdempotententKey: composeSigningIdempotentKey(msg.TxID, natMsg),
		},
	)
	if err != nil {
		logger.Error(
			"Failed to enqueue signing result event",
			err,
			"algorithm",
			algorithm,
			"walletID",
			msg.WalletID,
			"txID",
			msg.TxID,
		)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			fmt.Sprintf("Failed to enqueue %s signing result", algorithm),
			natMsg,
		)
		return
	}

	// Send reply and log success
	ec.sendReplyToRemoveMsg(natMsg)
	logger.Info(
		"[COMPLETED SIGN] signing completed successfully",
		"algorithm",
		algorithm,
		"walletID",
		msg.WalletID,
		"txID",
		msg.TxID,
	)
}

// runClassicSigning handles non-Taurus signing flows (ECDSA/EDDSA)
func (ec *eventConsumer) runClassicSigning(msg types.SignTxMessage, natMsg *nats.Msg) {
	var session mpc.SigningSession
	idempotentKey := composeSigningIdempotentKey(msg.TxID, natMsg)

	var sessionErr error
	switch msg.KeyType {
	case types.KeyTypeSecp256k1:
		session, sessionErr = ec.node.CreateSigningSession(
			mpc.SessionTypeECDSA,
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			ec.signingResultQueue,
			idempotentKey,
		)
	case types.KeyTypeEd25519:
		session, sessionErr = ec.node.CreateSigningSession(
			mpc.SessionTypeEDDSA,
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			ec.signingResultQueue,
			idempotentKey,
		)
	default:
		sessionErr = fmt.Errorf("unsupported key type: %v", msg.KeyType)
	}
	if sessionErr != nil {
		if errors.Is(sessionErr, mpc.ErrNotEnoughParticipants) {
			logger.Info(
				"RETRY LATER: Not enough participants to sign",
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"nodeID", ec.node.ID(),
			)
			//Return for retry later
			return
		}

		if errors.Is(sessionErr, mpc.ErrNotInParticipantList) {
			logger.Info("Node is not in participant list for this wallet, skipping signing",
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"nodeID", ec.node.ID(),
			)
			// Skip signing instead of treating as error
			return
		}

		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			sessionErr,
			"Failed to create signing session",
			natMsg,
		)
		return
	}

	txBigInt := new(big.Int).SetBytes(msg.Tx)
	err := session.Init(txBigInt)
	if err != nil {
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
	ec.warmUpSession()

	onSuccess := func(data []byte) {
		done()
		ec.sendReplyToRemoveMsg(natMsg)
	}
	go session.Sign(onSuccess)
}
