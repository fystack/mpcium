package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
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
	privKey             ed25519.PrivateKey
}

// Options defines configuration options for creating a new MPCClient
type Options struct {
	// NATS connection
	NatsConn *nats.Conn

	// Key path options
	KeyPath string // Path to unencrypted key (default: "./event_initiator.key")

	// Encryption options
	Encrypted bool   // Whether the key is encrypted
	Password  string // Password for encrypted key
}

// NewMPCClient creates a new MPC client using the provided options.
// It reads the Ed25519 private key from disk and sets up messaging connections.
// If the key is encrypted (.age file), decryption options must be provided in the config.
func NewMPCClient(opts Options) MPCClient {
	// Set default paths if not provided
	if opts.KeyPath == "" {
		opts.KeyPath = filepath.Join(".", "event_initiator.key")
	}

	if strings.HasSuffix(opts.KeyPath, ".age") {
		opts.Encrypted = true
	}

	var privHexBytes []byte
	var err error

	// Check if key file exists
	if _, err := os.Stat(opts.KeyPath); err == nil {
		if opts.Encrypted {
			// Encrypted key exists, try to decrypt it
			if opts.Password == "" {
				logger.Fatal("Encrypted key found but no decryption option provided", nil)
			}

			// Read encrypted file
			encryptedBytes, err := os.ReadFile(opts.KeyPath)
			if err != nil {
				logger.Fatal("Failed to read encrypted private key file", err)
			}

			// Decrypt the key using the provided password
			privHexBytes, err = decryptPrivateKey(encryptedBytes, opts.Password)
			if err != nil {
				logger.Fatal("Failed to decrypt private key", err)
			}
		} else {
			// Unencrypted key exists, read it normally
			privHexBytes, err = os.ReadFile(opts.KeyPath)
			if err != nil {
				logger.Fatal("Failed to read private key file", err)
			}
		}
	} else {
		logger.Fatal("No private key file found", nil)
	}

	privHex := string(privHexBytes)
	// Decode private key from hex
	privSeed, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Println("Failed to decode private key hex:", err)
		os.Exit(1)
	}

	// Reconstruct full Ed25519 private key from seed
	priv := ed25519.NewKeyFromSeed(privSeed)

	// 2) Create the PubSub for both publish & subscribe
	signingBroker, err := messaging.NewJetStreamBroker(context.Background(), opts.NatsConn, "mpc-signing", []string{
		"mpc.signing_request.*",
	})
	if err != nil {
		logger.Fatal("Failed to create signing jetstream broker", err)
	}
	keygenBroker, err := messaging.NewJetStreamBroker(context.Background(), opts.NatsConn, "mpc-keygen", []string{
		"mpc.keygen_request.*",
	})
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
		privKey:             priv,
	}
}

// decryptPrivateKey decrypts the encrypted private key using the provided password
func decryptPrivateKey(encryptedData []byte, password string) ([]byte, error) {
	// Create an age identity (decryption key) from the password
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity from password: %w", err)
	}

	// Create a reader from the encrypted data
	decrypter, err := age.Decrypt(strings.NewReader(string(encryptedData)), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypter: %w", err)
	}

	// Read the decrypted data
	decryptedData, err := io.ReadAll(decrypter)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decryptedData, nil
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
	// sign
	msg.Signature = ed25519.Sign(c.privKey, raw)

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
	// sign
	msg.Signature = ed25519.Sign(c.privKey, raw)

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("SignTransaction: marshal error: %w", err)
	}

	if err := c.signingBroker.PublishMessage(context.Background(), event.SigningRequestEventTopic, bytes); err != nil {
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
	// sign
	msg.Signature = ed25519.Sign(c.privKey, raw)

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
