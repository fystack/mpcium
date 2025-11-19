package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/eventconsumer"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

const (
	GenerateWalletSuccessTopic = "mpc.mpc_keygen_result.*"  // wildcard to listen to all success events
	ResharingSuccessTopic      = "mpc.mpc_reshare_result.*" // wildcard to listen to all success events
)

type MPCClient interface {
	CreateWallet(msg *types.GenerateKeyMessage) error
	OnWalletCreationResult(callback func(event event.KeygenResultEvent)) error

	SignTransaction(msg *types.SignTxMessage) error
	OnSignResult(callback func(event event.SigningResultEvent)) error

	Resharing(msg *types.ResharingMessage) error
	OnResharingResult(callback func(event event.ResharingResultEvent)) error

	PresignTransaction(msg *types.PresignTxMessage) error
	OnPresignResult(callback func(event event.PresignResultEvent)) error
}

type mpcClient struct {
	signingBroker       messaging.MessageBroker
	keygenBroker        messaging.MessageBroker
	pubsub              messaging.PubSub
	genKeySuccessQueue  messaging.MessageQueue
	signResultQueue     messaging.MessageQueue
	reshareSuccessQueue messaging.MessageQueue
	presignSuccessQueue messaging.MessageQueue
	signer              Signer
}

// Options defines configuration options for creating a new MPCClient
type Options struct {
	// NATS connection
	NatsConn *nats.Conn

	// Signer for signing messages
	Signer Signer
}

// NewMPCClient creates a new MPC client using the provided options.
// The signer must be provided to handle message signing.
func NewMPCClient(opts Options) MPCClient {
	if opts.Signer == nil {
		logger.Fatal("Signer is required", nil)
	}

	// 2) Create the PubSub for both publish & subscribe
	signingBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		"mpc-signing",
		[]string{
			"mpc.signing_request.*",
		},
	)
	if err != nil {
		logger.Fatal("Failed to create signing jetstream broker", err)
	}
	keygenBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		"mpc-keygen",
		[]string{
			"mpc.keygen_request.*",
		},
	)
	if err != nil {
		logger.Fatal("Failed to create keygen jetstream broker", err)
	}

	pubsub := messaging.NewNATSPubSub(opts.NatsConn)

	manager := messaging.NewNATsMessageQueueManager("mpc", []string{
		"mpc.mpc_keygen_result.*",
		"mpc.mpc_signing_result.*",
		"mpc.mpc_reshare_result.*",
		"mpc.mpc_presign_result.*",
	}, opts.NatsConn)

	genKeySuccessQueue := manager.NewMessageQueue("mpc_keygen_result")
	signResultQueue := manager.NewMessageQueue("mpc_signing_result")
	reshareSuccessQueue := manager.NewMessageQueue("mpc_reshare_result")
	presignSuccessQueue := manager.NewMessageQueue("mpc_presign_result")

	return &mpcClient{
		signingBroker:       signingBroker,
		keygenBroker:        keygenBroker,
		pubsub:              pubsub,
		genKeySuccessQueue:  genKeySuccessQueue,
		signResultQueue:     signResultQueue,
		reshareSuccessQueue: reshareSuccessQueue,
		presignSuccessQueue: presignSuccessQueue,
		signer:              opts.Signer,
	}
}

// CreateWallet generates a GenerateKeyMessage, signs it, and publishes it.
func (c *mpcClient) CreateWallet(msg *types.GenerateKeyMessage) error {
	// compute the canonical raw bytes
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("CreateWallet: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("CreateWallet: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("CreateWallet: marshal error: %w", err)
	}

	if err := c.keygenBroker.PublishMessage(context.Background(), event.KeygenRequestTopic, bytes); err != nil {
		return fmt.Errorf("CreateWallet: publish error: %w", err)
	}
	return nil
}

// The callback will be invoked whenever a wallet creation result is received.
func (c *mpcClient) OnWalletCreationResult(callback func(event event.KeygenResultEvent)) error {
	err := c.genKeySuccessQueue.Dequeue(GenerateWalletSuccessTopic, func(msg []byte) error {
		var event event.KeygenResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnWalletCreationResult: subscribe error: %w", err)
	}

	return nil
}

// SignTransaction builds a SignTxMessage, signs it, and publishes it.
func (c *mpcClient) SignTransaction(msg *types.SignTxMessage) error {
	// compute the canonical raw bytes (omitting Signature field)
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("SignTransaction: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("SignTransaction: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("SignTransaction: marshal error: %w", err)
	}

	if err := c.signingBroker.PublishMessage(context.Background(), event.SigningRequestTopic, bytes); err != nil {
		return fmt.Errorf("SignTransaction: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnSignResult(callback func(event event.SigningResultEvent)) error {
	err := c.signResultQueue.Dequeue(event.SigningResultCompleteTopic, func(msg []byte) error {
		var event event.SigningResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnSignResult: subscribe error: %w", err)
	}

	return nil
}

func (c *mpcClient) Resharing(msg *types.ResharingMessage) error {
	// compute the canonical raw bytes
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("Resharing: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("Resharing: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Resharing: marshal error: %w", err)
	}

	if err := c.pubsub.Publish(eventconsumer.MPCReshareEvent, bytes); err != nil {
		return fmt.Errorf("Resharing: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnResharingResult(callback func(event event.ResharingResultEvent)) error {

	err := c.reshareSuccessQueue.Dequeue(ResharingSuccessTopic, func(msg []byte) error {
		logger.Info("Received reshare success message", "raw", string(msg))
		var event event.ResharingResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			logger.Error("Failed to unmarshal reshare success event", err, "raw", string(msg))
			return err
		}
		logger.Info("Deserialized reshare success event", "event", event)
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnResharingResult: subscribe error: %w", err)
	}

	return nil
}

func (c *mpcClient) PresignTransaction(msg *types.PresignTxMessage) error {
	// compute the canonical raw bytes
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("PresignTransaction: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("PresignTransaction: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("PresignTransaction: marshal error: %w", err)
	}

	if err := c.pubsub.Publish(eventconsumer.MPCPresignEvent, bytes); err != nil {
		return fmt.Errorf("PresignTransaction: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnPresignResult(callback func(event event.PresignResultEvent)) error {
	err := c.presignSuccessQueue.Dequeue(event.PresignResultTopic, func(msg []byte) error {
		var event event.PresignResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnPresignResult: subscribe error: %w", err)
	}

	return nil
}
