package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	defaultKeyPath = "./event_initiator.key"
	keyFileExt     = ".age"

	// NATS stream names
	mpcSigningStream = "mpc-signing"

	// NATS queue names
	mpcKeygenSuccessQueue    = "mpc_keygen_success"
	mpcSigningResultQueue    = "signing_result"
	mpcResharingSuccessQueue = "mpc_resharing_success"

	// NATS subjects
	mpcSigningRequestSubject   = "mpc.signing_request.*"
	mpcKeygenSuccessSubject    = "mpc.mpc_keygen_success.*"
	mpcSigningResultSubject    = "mpc.signing_result.*"
	mpcResharingSuccessSubject = "mpc.mpc_resharing_success.*"
)

type MPCClient interface {
	CreateWallet(walletID string) error
	OnWalletCreationResult(callback func(event.KeygenSuccessEvent)) error

	SignTransaction(msg *types.SignTxMessage) error
	OnSignResult(callback func(event.SigningResultEvent)) error

	Resharing(walletID string, newThreshold int, keyType types.KeyType) error
	OnResharingResult(callback func(event.ResharingSuccessEvent)) error
}

type mpcClient struct {
	signingStream        messaging.StreamPubsub
	pubsub               messaging.PubSub
	genKeySuccessQueue   messaging.MessageQueue
	signResultQueue      messaging.MessageQueue
	resharingResultQueue messaging.MessageQueue
	privKey              ed25519.PrivateKey
}

// Options defines configuration options for creating a new MPCClient
type Options struct {
	NatsConn  *nats.Conn
	KeyPath   string // Path to unencrypted key (default: "./event_initiator.key")
	Encrypted bool   // Whether the key is encrypted
	Password  string // Password for encrypted key
}

// NewMPCClient creates a new MPC client using the provided options.
func NewMPCClient(opts Options) MPCClient {
	// Set default key path if not provided
	if opts.KeyPath == "" {
		opts.KeyPath = defaultKeyPath
	}

	// Auto-detect encryption based on file extension
	if strings.HasSuffix(opts.KeyPath, keyFileExt) {
		opts.Encrypted = true
	}

	// Load private key
	privKey := loadPrivateKey(opts)

	// Initialize messaging components
	signingStream := initSigningStream(opts.NatsConn)
	pubsub := messaging.NewNATSPubSub(opts.NatsConn)
	manager := initMessageQueueManager(opts.NatsConn)

	return &mpcClient{
		signingStream:        signingStream,
		pubsub:               pubsub,
		genKeySuccessQueue:   manager.NewMessageQueue(mpcKeygenSuccessQueue),
		signResultQueue:      manager.NewMessageQueue(mpcSigningResultQueue),
		resharingResultQueue: manager.NewMessageQueue(mpcResharingSuccessQueue),
		privKey:              privKey,
	}
}

func initMessageQueueManager(natsConn *nats.Conn) *messaging.NATsMessageQueueManager {
	return messaging.NewNATsMessageQueueManager("mpc", []string{
		mpcKeygenSuccessSubject,
		mpcSigningResultSubject,
		mpcResharingSuccessSubject,
	}, natsConn)
}

// CreateWallet generates a GenerateKeyMessage, signs it, and publishes it.
func (c *mpcClient) CreateWallet(walletID string) error {
	msg := &types.GenerateKeyMessage{WalletID: walletID}

	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("CreateWallet: raw payload error: %w", err)
	}

	msg.Signature = ed25519.Sign(c.privKey, raw)
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("CreateWallet: marshal error: %w", err)
	}

	if err := c.pubsub.Publish(eventconsumer.MPCGenerateEvent, bytes); err != nil {
		return fmt.Errorf("CreateWallet: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnWalletCreationResult(callback func(event.KeygenSuccessEvent)) error {
	return c.handleQueueEvent(c.genKeySuccessQueue, event.KeygenSuccessEventTopic, callback)
}

func (c *mpcClient) SignTransaction(msg *types.SignTxMessage) error {
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("SignTransaction: raw payload error: %w", err)
	}

	msg.Signature = ed25519.Sign(c.privKey, raw)
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("SignTransaction: marshal error: %w", err)
	}

	if err := c.signingStream.Publish(event.SigningRequestEventTopic, bytes); err != nil {
		return fmt.Errorf("SignTransaction: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnSignResult(callback func(event.SigningResultEvent)) error {
	return c.handleQueueEvent(c.signResultQueue, event.SigningResultCompleteTopic, callback)
}

func (c *mpcClient) Resharing(walletID string, newThreshold int, keyType types.KeyType) error {
	msg := &types.ResharingMessage{
		WalletID:     walletID,
		NewThreshold: newThreshold,
		KeyType:      keyType,
	}

	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("Resharing: raw payload error: %w", err)
	}

	msg.Signature = ed25519.Sign(c.privKey, raw)
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Resharing: marshal error: %w", err)
	}

	if err := c.pubsub.Publish(eventconsumer.MPCResharingEvent, bytes); err != nil {
		return fmt.Errorf("Resharing: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnResharingResult(callback func(event.ResharingSuccessEvent)) error {
	return c.handleQueueEvent(c.resharingResultQueue, event.ResharingSuccessEventTopic, callback)
}

// Generic handler for queue events
func (c *mpcClient) handleQueueEvent(queue messaging.MessageQueue, topic string, callback interface{}) error {
	return queue.Dequeue(topic, func(msg []byte) error {
		switch cb := callback.(type) {
		case func(event.KeygenSuccessEvent):
			var event event.KeygenSuccessEvent
			if err := json.Unmarshal(msg, &event); err != nil {
				return err
			}
			cb(event)
		case func(event.SigningResultEvent):
			var event event.SigningResultEvent
			if err := json.Unmarshal(msg, &event); err != nil {
				return err
			}
			cb(event)
		case func(event.ResharingSuccessEvent):
			var event event.ResharingSuccessEvent
			if err := json.Unmarshal(msg, &event); err != nil {
				return err
			}
			cb(event)
		default:
			return fmt.Errorf("unsupported callback type")
		}
		return nil
	})
}

func loadPrivateKey(opts Options) ed25519.PrivateKey {
	if _, err := os.Stat(opts.KeyPath); os.IsNotExist(err) {
		logger.Fatal("No private key file found", nil)
	}

	var privHexBytes []byte
	var err error

	if opts.Encrypted {
		if opts.Password == "" {
			logger.Fatal("Encrypted key found but no decryption option provided", nil)
		}
		privHexBytes, err = loadEncryptedKey(opts.KeyPath, opts.Password)
	} else {
		privHexBytes, err = os.ReadFile(opts.KeyPath)
	}

	if err != nil {
		logger.Fatal("Failed to read private key file", err)
	}

	privSeed, err := hex.DecodeString(string(privHexBytes))
	if err != nil {
		logger.Fatal("Failed to decode private key hex", err)
	}

	return ed25519.NewKeyFromSeed(privSeed)
}

func loadEncryptedKey(keyPath, password string) ([]byte, error) {
	encryptedBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file: %w", err)
	}

	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity from password: %w", err)
	}

	decrypter, err := age.Decrypt(strings.NewReader(string(encryptedBytes)), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypter: %w", err)
	}

	return io.ReadAll(decrypter)
}

func initSigningStream(natsConn *nats.Conn) messaging.StreamPubsub {
	stream, err := messaging.NewJetStreamPubSub(natsConn, mpcSigningStream, []string{mpcSigningRequestSubject})
	if err != nil {
		logger.Fatal("Failed to create JetStream PubSub", err)
	}
	return stream
}
