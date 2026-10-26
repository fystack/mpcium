package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	CreateWallet(walletID string) error
	OnWalletCreationResult(callback func(event event.KeygenResultEvent)) error

	SignTransaction(msg *types.SignTxMessage) error
	OnSignResult(callback func(event event.SigningResultEvent)) error

	Resharing(msg *types.ResharingMessage) error
	OnResharingResult(callback func(event event.ResharingResultEvent)) error
}

type mpcClient struct {
	signingBroker       messaging.MessageBroker
	keygenBroker        messaging.MessageBroker
	pubsub              messaging.PubSub
	genKeySuccessQueue  messaging.MessageQueue
	signResultQueue     messaging.MessageQueue
	reshareSuccessQueue messaging.MessageQueue
	signer              Signer
	nodeKeyLookup       event.NodeKeyLookup
	requiredNodeSigs    int
	// reshareRequiredSigs maps a resharing session ID to the new committee threshold (t+1) it requested.
	reshareRequiredSigs sync.Map
}

// Options defines configuration options for creating a new MPCClient
type Options struct {
	// NATS connection
	NatsConn *nats.Conn

	// Signer for signing messages
	Signer Signer

	// NodeKeyLookup, when set, is used to verify that result events (keygen,
	// signing, resharing) were signed by a known MPC node. Results without a
	// valid node signature are rejected. See NewNodeKeyLookup.
	NodeKeyLookup event.NodeKeyLookup

	// RequiredNodeSignatures is how many distinct nodes must sign the same result (t+1); <= 1 delivers the first one.
	RequiredNodeSignatures int
}

// NewMPCClient creates a new MPC client using the provided options.
// The signer must be provided to handle message signing.
func NewMPCClient(opts Options) MPCClient {
	if opts.Signer == nil {
		logger.Fatal("Signer is required", nil)
	}
	if opts.RequiredNodeSignatures > 1 && opts.NodeKeyLookup == nil {
		logger.Fatal("NodeKeyLookup is required when RequiredNodeSignatures > 1", nil)
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
	}, opts.NatsConn)

	genKeySuccessQueue := manager.NewMessageQueue("mpc_keygen_result")
	signResultQueue := manager.NewMessageQueue("mpc_signing_result")
	reshareSuccessQueue := manager.NewMessageQueue("mpc_reshare_result")

	return &mpcClient{
		signingBroker:       signingBroker,
		keygenBroker:        keygenBroker,
		pubsub:              pubsub,
		genKeySuccessQueue:  genKeySuccessQueue,
		signResultQueue:     signResultQueue,
		reshareSuccessQueue: reshareSuccessQueue,
		signer:              opts.Signer,
		nodeKeyLookup:       opts.NodeKeyLookup,
		requiredNodeSigs:    opts.RequiredNodeSignatures,
	}
}

// CreateWallet generates a GenerateKeyMessage, signs it, and publishes it.
func (c *mpcClient) CreateWallet(walletID string) error {
	// build the message
	msg := &types.GenerateKeyMessage{
		WalletID: walletID,
	}
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
	aggregator := walletResultAggregator(c.requiredNodeSigs, callback)
	err := c.genKeySuccessQueue.Dequeue(GenerateWalletSuccessTopic, func(msg []byte) error {
		var event event.KeygenResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		if err := c.verifyResult(event.NodeID, event.ResultSignature, &event); err != nil {
			return err
		}
		aggregator.Add(event)
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
	aggregator := signingResultAggregator(c.requiredNodeSigs, callback)
	err := c.signResultQueue.Dequeue(event.SigningResultCompleteTopic, func(msg []byte) error {
		var event event.SigningResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		if err := c.verifyResult(event.NodeID, event.ResultSignature, &event); err != nil {
			return err
		}
		aggregator.Add(event)
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

	c.reshareRequiredSigs.Store(msg.SessionID, msg.NewThreshold+1)

	if err := c.pubsub.Publish(eventconsumer.MPCReshareEvent, bytes); err != nil {
		return fmt.Errorf("Resharing: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnResharingResult(callback func(event event.ResharingResultEvent)) error {

	aggregator := reshareResultAggregator(c.reshareRequiredFor, func(e event.ResharingResultEvent) {
		c.reshareRequiredSigs.Delete(e.SessionID)
		callback(e)
	})
	err := c.reshareSuccessQueue.Dequeue(ResharingSuccessTopic, func(msg []byte) error {
		logger.Info("Received reshare success message", "raw", string(msg))
		var event event.ResharingResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			logger.Error("Failed to unmarshal reshare success event", err, "raw", string(msg))
			return err
		}
		if err := c.verifyResult(event.NodeID, event.ResultSignature, &event); err != nil {
			return err
		}
		logger.Info("Deserialized reshare success event", "event", event)
		aggregator.Add(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnResharingResult: subscribe error: %w", err)
	}

	return nil
}

// verifyResult checks a node-signed result event. Failed verification returns
// messaging.ErrPermament so the message is terminated instead of redelivered.
func (c *mpcClient) verifyResult(nodeID string, signature []byte, res interface{ Raw() ([]byte, error) }) error {
	if c.nodeKeyLookup == nil {
		return nil
	}
	if err := event.VerifyNodeResult(nodeID, signature, res, c.nodeKeyLookup); err != nil {
		logger.Error("Rejecting result event", err)
		return messaging.ErrPermament
	}
	return nil
}

// NewNodeKeyLookup builds a NodeKeyLookup from a directory of node identity
// files (<node_name>_identity.json) as produced by mpcium-cli generate-identity.
func NewNodeKeyLookup(identityDir string) (event.NodeKeyLookup, error) {
	entries, err := os.ReadDir(identityDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity directory: %w", err)
	}

	type nodeIdentity struct {
		NodeID    string `json:"node_id"`
		PublicKey string `json:"public_key"`
	}

	keys := make(map[string][]byte)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_identity.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(identityDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), err)
		}
		var identity nodeIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", entry.Name(), err)
		}
		publicKey, err := hex.DecodeString(identity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key in %s: %w", entry.Name(), err)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key size in %s: %d", entry.Name(), len(publicKey))
		}
		keys[identity.NodeID] = publicKey
	}

	return func(nodeID string) ([]byte, error) {
		publicKey, ok := keys[nodeID]
		if !ok {
			return nil, fmt.Errorf("unknown node: %s", nodeID)
		}
		return publicKey, nil
	}, nil
}

func (c *mpcClient) reshareRequiredFor(e event.ResharingResultEvent) int {
	if c.requiredNodeSigs <= 1 {
		return c.requiredNodeSigs
	}
	if required, ok := c.reshareRequiredSigs.Load(e.SessionID); ok {
		return required.(int)
	}
	return c.requiredNodeSigs
}
