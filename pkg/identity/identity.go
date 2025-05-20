package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"filippo.io/age"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// NodeIdentity represents a node's identity information
type NodeIdentity struct {
	NodeName  string `json:"node_name"`
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

// Store manages node identities
type Store interface {
	// GetPublicKey retrieves a node's public key by its ID
	GetPublicKey(nodeID string) ([]byte, error)
	VerifyInitiatorMessage(msg types.InitiatorMessage) error
	SignMessage(msg *types.TssMessage) ([]byte, error)
	VerifyMessage(msg *types.TssMessage) error
}

// fileStore implements the Store interface using the filesystem
type fileStore struct {
	identityDir     string
	currentNodeName string

	// Cache for public keys by node_id
	publicKeys map[string][]byte
	mu         sync.RWMutex

	// Cached private key
	privateKey      []byte
	initiatorPubKey []byte
}

// NewFileStore creates a new identity store
func NewFileStore(identityDir, nodeName string, decrypt bool) (*fileStore, error) {
	if err := os.MkdirAll(identityDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create identity directory: %w", err)
	}

	privateKeyHex, err := loadPrivateKey(identityDir, nodeName, decrypt)
	if err != nil {
		return nil, err
	}

	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %w", err)
	}

	pubKeyHex := viper.GetString("event_initiator_pubkey")
	if pubKeyHex == "" {
		return nil, fmt.Errorf("event_initiator_pubkey not found in quax config")
	}
	initiatorPubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid initiator public key format: %w", err)
	}

	logger.Infof("Loaded initiator public key for node %s", pubKeyHex)

	// Load peers.json to validate all nodes have identity files
	peersData, err := os.ReadFile("peers.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read peers.json: %w", err)
	}

	peers := make(map[string]string)
	if err := json.Unmarshal(peersData, &peers); err != nil {
		return nil, fmt.Errorf("failed to parse peers.json: %w", err)
	}

	store := &fileStore{
		identityDir:     identityDir,
		currentNodeName: nodeName,
		publicKeys:      make(map[string][]byte),
		privateKey:      privateKey,
		initiatorPubKey: initiatorPubKey,
	}

	// Check that each node in peers.json has an identity file
	for nodeName, nodeID := range peers {
		identityFilePath := filepath.Join(identityDir, fmt.Sprintf("%s_identity.json", nodeName))
		data, err := os.ReadFile(identityFilePath)
		if err != nil {
			return nil, fmt.Errorf("missing identity file for node %s (%s): %w", nodeName, nodeID, err)
		}

		var identity NodeIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			return nil, fmt.Errorf("failed to parse identity file for node %s: %w", nodeName, err)
		}

		// Verify that the nodeID in peers.json matches the one in the identity file
		if identity.NodeID != nodeID {
			return nil, fmt.Errorf("node ID mismatch for %s: %s in peers.json vs %s in identity file",
				nodeName, nodeID, identity.NodeID)
		}

		key, err := hex.DecodeString(identity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key format for node %s: %w", nodeName, err)
		}

		store.publicKeys[identity.NodeID] = key
	}

	return store, nil
}

// loadPrivateKey loads the private key from file, decrypting if necessary
func loadPrivateKey(identityDir, nodeName string, decrypt bool) (string, error) {
	// Check for encrypted or unencrypted private key
	encryptedKeyPath := filepath.Join(identityDir, fmt.Sprintf("%s_private.key.age", nodeName))
	unencryptedKeyPath := filepath.Join(identityDir, fmt.Sprintf("%s_private.key", nodeName))

	if decrypt {
		// Use the encrypted age file
		if _, err := os.Stat(encryptedKeyPath); err != nil {
			return "", fmt.Errorf("no encrypted private key found for node %s", nodeName)
		}

		logger.Infof("Using age-encrypted private key for %s", nodeName)

		// Open the encrypted file
		encryptedFile, err := os.Open(encryptedKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to open encrypted key file: %w", err)
		}
		defer encryptedFile.Close()

		// Prompt for passphrase using term.ReadPassword
		fmt.Print("Enter passphrase to decrypt private key: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // newline after prompt
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}
		passphrase := string(bytePassword)
		// Create an identity with the provided passphrase
		identity, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return "", fmt.Errorf("failed to create identity for decryption: %w", err)
		}

		// Decrypt the file
		decrypter, err := age.Decrypt(encryptedFile, identity)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt private key: %w", err)
		}

		// Read the decrypted content
		decryptedData, err := io.ReadAll(decrypter)
		if err != nil {
			return "", fmt.Errorf("failed to read decrypted key: %w", err)
		}

		return string(decryptedData), nil
	} else {
		// Use the unencrypted private key file
		if _, err := os.Stat(unencryptedKeyPath); err != nil {
			return "", fmt.Errorf("no unencrypted private key found for node %s", nodeName)
		}

		logger.Infof("Using unencrypted private key for %s", nodeName)
		privateKeyData, err := os.ReadFile(unencryptedKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to read private key file: %w", err)
		}
		return string(privateKeyData), nil
	}
}

// GetPublicKey retrieves a node's public key by its ID
func (s *fileStore) GetPublicKey(nodeID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if key, exists := s.publicKeys[nodeID]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("public key not found for node ID: %s", nodeID)
}

func (s *fileStore) SignMessage(msg *types.TssMessage) ([]byte, error) {
	// Get deterministic bytes for signing
	msgBytes, err := msg.MarshalForSigning()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message for signing: %w", err)
	}

	signature := ed25519.Sign(s.privateKey, msgBytes)
	return signature, nil
}

// VerifyMessage verifies a TSS message's signature using the sender's public key
func (s *fileStore) VerifyMessage(msg *types.TssMessage) error {
	if msg.Signature == nil {
		return fmt.Errorf("message has no signature")
	}

	// Get the sender's NodeID
	senderNodeID := partyIDToNodeID(msg.From)

	// Get the sender's public key
	publicKey, err := s.GetPublicKey(senderNodeID)
	if err != nil {
		return fmt.Errorf("failed to get sender's public key: %w", err)
	}

	// Get deterministic bytes for verification
	msgBytes, err := msg.MarshalForSigning()
	if err != nil {
		return fmt.Errorf("failed to marshal message for verification: %w", err)
	}

	// Verify the signature
	if !ed25519.Verify(publicKey, msgBytes, msg.Signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// VerifyInitiatorMessage verifies that a message was signed by the known initiator
func (s *fileStore) VerifyInitiatorMessage(msg types.InitiatorMessage) error {
	// Get the raw message that was signed
	msgBytes, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}

	// Get the signature
	signature := msg.Sig()
	if signature == nil || len(signature) == 0 {
		return fmt.Errorf("message has no signature")
	}

	// Verify the signature using the initiator's public key
	if !ed25519.Verify(s.initiatorPubKey, msgBytes, signature) {
		return fmt.Errorf("invalid signature from initiator")
	}

	return nil
}

func partyIDToNodeID(partyID *tss.PartyID) string {
	return strings.Split(string(partyID.KeyInt().Bytes()), ":")[0]
}
