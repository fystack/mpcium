package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"

	"filippo.io/age"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"golang.org/x/term"

	"github.com/fystack/mpcium/pkg/common/pathutil"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/spf13/viper"
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

	SignEcdhMessage(msg *types.ECDHMessage) ([]byte, error)
	VerifySignature(msg *types.ECDHMessage) error

	SetSymmetricKey(peerID string, key []byte)
	GetSymmetricKey(peerID string) ([]byte, error)
	RemoveSymmetricKey(peerID string)
	GetSymetricKeyCount() int
	CheckSymmetricKeyComplete(desired int) bool

	EncryptMessage(plaintext []byte, peerID string) ([]byte, error)
	DecryptMessage(cipher []byte, peerID string) ([]byte, error)
}

type InitiatorKey struct {
	Algorithm types.KeyType
	Ed25519   []byte
	P256      *ecdsa.PublicKey
}

// fileStore implements the Store interface using the filesystem
type fileStore struct {
	identityDir     string
	currentNodeName string

	// Cache for public keys by node_id
	publicKeys map[string][]byte
	mu         sync.RWMutex

	privateKey    []byte
	initiatorKey  *InitiatorKey
	symmetricKeys map[string][]byte
}

// NewFileStore creates a new identity store
func NewFileStore(identityDir, nodeName string, decrypt bool) (*fileStore, error) {
	if err := os.MkdirAll(identityDir, 0750); err != nil {
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

	initiatorKey, err := loadInitiatorKeys()
	if err != nil {
		return nil, err
	}

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
		initiatorKey:    initiatorKey,
		symmetricKeys:   make(map[string][]byte),
	}

	// Check that each node in peers.json has an identity file
	for nodeName, nodeID := range peers {
		identityFileName := fmt.Sprintf("%s_identity.json", nodeName)
		identityFilePath, err := pathutil.SafePath(identityDir, identityFileName)
		if err != nil {
			return nil, fmt.Errorf("invalid identity file path for node %s: %w", nodeName, err)
		}

		data, err := os.ReadFile(identityFilePath)
		if err != nil {
			return nil, fmt.Errorf(
				"missing identity file for node %s (%s): %w",
				nodeName,
				nodeID,
				err,
			)
		}

		var identity NodeIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			return nil, fmt.Errorf("failed to parse identity file for node %s: %w", nodeName, err)
		}

		// Verify that the nodeID in peers.json matches the one in the identity file
		if identity.NodeID != nodeID {
			return nil, fmt.Errorf(
				"node ID mismatch for %s: %s in peers.json vs %s in identity file",
				nodeName,
				nodeID,
				identity.NodeID,
			)
		}

		key, err := hex.DecodeString(identity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key format for node %s: %w", nodeName, err)
		}

		store.publicKeys[identity.NodeID] = key
	}

	return store, nil
}

func loadInitiatorKeys() (*InitiatorKey, error) {
	// Get algorithm configuration with default
	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.KeyTypeEd25519)
	}

	// Validate algorithm
	if !slices.Contains(
		[]string{string(types.KeyTypeEd25519), string(types.KeyTypeP256)},
		algorithm,
	) {
		return nil, fmt.Errorf("invalid algorithm: %s. Must be %s or %s",
			algorithm,
			types.KeyTypeEd25519,
			types.KeyTypeP256,
		)
	}

	var initiatorKey *InitiatorKey

	switch algorithm {
	case string(types.KeyTypeEd25519):
		key, err := loadEd25519InitiatorKey()
		if err != nil {
			return nil, fmt.Errorf("failed to load Ed25519 initiator key: %w", err)
		}
		initiatorKey = &InitiatorKey{
			Algorithm: "ed25519",
			Ed25519:   key,
		}
		logger.Infof("Loaded Ed25519 initiator public key")

	case string(types.KeyTypeP256):
		key, err := loadP256InitiatorKey()
		if err != nil {
			return nil, fmt.Errorf("failed to load P-256 initiator key: %w", err)
		}
		initiatorKey = &InitiatorKey{
			Algorithm: "p256",
			P256:      key,
		}
		logger.Infof(
			"Loaded P-256 initiator public key from %s",
			viper.GetString("event_initiator_pubkey"),
		)
	}

	return initiatorKey, nil
}

// loadEd25519InitiatorKey loads Ed25519 initiator public key
func loadEd25519InitiatorKey() ([]byte, error) {
	pubKeyHex := viper.GetString("event_initiator_pubkey")
	if pubKeyHex == "" {
		return nil, fmt.Errorf("event_initiator_pubkey not found in config")
	}

	key, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid initiator public key format: %w", err)
	}

	return key, nil
}

func loadP256InitiatorKey() (*ecdsa.PublicKey, error) {
	pubKeyHex := viper.GetString("event_initiator_pubkey")
	if pubKeyHex == "" {
		return nil, fmt.Errorf("event_initiator_pubkey not found in config")
	}

	// Use the new P256 functions from p256.go
	publicKey, err := encryption.ParseP256PublicKeyFromHex(pubKeyHex)
	if err == nil {
		return publicKey, nil
	}

	// If hex parsing fails, try base64
	publicKey, err = encryption.ParseP256PublicKeyFromBase64(pubKeyHex)
	if err == nil {
		return publicKey, nil
	}

	return nil, fmt.Errorf(
		"failed to decode event_initiator_pubkey as hex or base64: %w",
		err,
	)
}

// loadPrivateKey loads the private key from file, decrypting if necessary
func loadPrivateKey(identityDir, nodeName string, decrypt bool) (string, error) {
	// Check for encrypted or unencrypted private key
	encryptedKeyFileName := fmt.Sprintf("%s_private.key.age", nodeName)
	unencryptedKeyFileName := fmt.Sprintf("%s_private.key", nodeName)

	encryptedKeyPath, err := pathutil.SafePath(identityDir, encryptedKeyFileName)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted key path for node %s: %w", nodeName, err)
	}

	unencryptedKeyPath, err := pathutil.SafePath(identityDir, unencryptedKeyFileName)
	if err != nil {
		return "", fmt.Errorf("invalid unencrypted key path for node %s: %w", nodeName, err)
	}

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

// Set SymmetricKey: adds or updates a symmetric key for a given peer ID.
func (s *fileStore) SetSymmetricKey(peerID string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.symmetricKeys[peerID] = key
}

// Get SymmetricKey: retrieves a peer node's dh symmetric-key by its ID
func (s *fileStore) GetSymmetricKey(peerID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if key, exists := s.symmetricKeys[peerID]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("SymmetricKey key not found for node ID: %s", peerID)
}

func (s *fileStore) RemoveSymmetricKey(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.symmetricKeys, peerID)
}

func (s *fileStore) GetSymetricKeyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.symmetricKeys)
}

func (s *fileStore) CheckSymmetricKeyComplete(desired int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.symmetricKeys) == desired
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

func (s *fileStore) EncryptMessage(plaintext []byte, peerID string) ([]byte, error) {
	key, err := s.GetSymmetricKey(peerID)
	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, fmt.Errorf("no symmetric key for peer %s", peerID)
	}

	return encryption.EncryptAESGCMWithNonceEmbed(plaintext, key)
}

func (s *fileStore) DecryptMessage(cipher []byte, peerID string) ([]byte, error) {
	key, err := s.GetSymmetricKey(peerID)

	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, fmt.Errorf("no symmetric key for peer %s", peerID)
	}
	return encryption.DecryptAESGCMWithNonceEmbed(cipher, key)
}

// Sign ECDH key exchange message
func (s *fileStore) SignEcdhMessage(msg *types.ECDHMessage) ([]byte, error) {
	// Get deterministic bytes for signing
	msgBytes, err := msg.MarshalForSigning()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message for signing: %w", err)
	}

	signature := ed25519.Sign(s.privateKey, msgBytes)
	return signature, nil
}

// Verify ECDH key exchange message
func (s *fileStore) VerifySignature(msg *types.ECDHMessage) error {
	if msg.Signature == nil {
		return fmt.Errorf("ECDH message has no signature")
	}

	// Get the sender's public key
	senderPk, err := s.GetPublicKey(msg.From)
	if err != nil {
		return fmt.Errorf("failed to get sender's public key: %w", err)
	}

	// Get deterministic bytes for verification
	msgBytes, err := msg.MarshalForSigning()
	if err != nil {
		return fmt.Errorf("failed to marshal message for verification: %w", err)
	}

	// Verify the signature
	if !ed25519.Verify(senderPk, msgBytes, msg.Signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func (s *fileStore) VerifyInitiatorMessage(msg types.InitiatorMessage) error {
	algo := s.initiatorKey.Algorithm

	switch algo {
	case types.KeyTypeEd25519:
		return s.verifyEd25519(msg)
	case types.KeyTypeP256:
		return s.verifyP256(msg)
	}
	return fmt.Errorf("unsupported algorithm: %s", algo)
}

func (s *fileStore) verifyEd25519(msg types.InitiatorMessage) error {
	msgBytes, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}
	signature := msg.Sig()
	if len(signature) == 0 {
		return errors.New("signature is empty")
	}

	if !ed25519.Verify(s.initiatorKey.Ed25519, msgBytes, signature) {
		return fmt.Errorf("invalid signature from initiator")
	}
	return nil
}

func (s *fileStore) verifyP256(msg types.InitiatorMessage) error {
	msgBytes, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}
	signature := msg.Sig()

	if s.initiatorKey.P256 == nil {
		return fmt.Errorf("initiator public key for secp256r1 is not set")
	}

	return encryption.VerifyP256Signature(s.initiatorKey.P256, msgBytes, signature)
}

func partyIDToNodeID(partyID *tss.PartyID) string {
	return strings.Split(string(partyID.KeyInt().Bytes()), ":")[0]
}
