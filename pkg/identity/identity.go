package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	AuthorizeInitiatorMessage(operation string, msg types.InitiatorMessage) error
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

// fileStore implements the Store interface using the filesystem
type fileStore struct {
	identityDir     string
	currentNodeName string

	// Cache for public keys by node_id
	publicKeys map[string][]byte
	mu         sync.RWMutex

	privateKey      []byte
	initiatorPubKey []byte
	symmetricKeys   map[string][]byte

	// Cached authorizer public keys by authorizer ID
	authorizerPubKeys map[string][]byte
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
		identityDir:       identityDir,
		currentNodeName:   nodeName,
		publicKeys:        make(map[string][]byte),
		privateKey:        privateKey,
		initiatorPubKey:   initiatorPubKey,
		authorizerPubKeys: make(map[string][]byte),
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

	// Load authorizer public keys from configuration if present
	authzAuthorizers := viper.GetStringMap("authorization.authorizers")
	for id, v := range authzAuthorizers {
		// v is expected to be a map with key "pubkey"
		if entry, ok := v.(map[string]interface{}); ok {
			if pubHexRaw, ok := entry["pubkey"]; ok {
				pubHex, ok := pubHexRaw.(string)
				if !ok || pubHex == "" {
					logger.Warn("Invalid or empty pubkey for authorizer", "authorizerID", id)
					continue
				}
				key, err := hex.DecodeString(pubHex)
				if err != nil {
					logger.Warn("Invalid hex pubkey for authorizer", "authorizerID", id, "error", err)
					continue
				}
				store.authorizerPubKeys[id] = key
			}
		}
	}

	return store, nil
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

// VerifyInitiatorMessage verifies that a message was signed by the known initiator
func (s *fileStore) VerifyInitiatorMessage(msg types.InitiatorMessage) error {
	// Get the raw message that was signed
	msgBytes, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}

	// Get the signature
	signature := msg.Sig()
	if len(signature) == 0 {
		return errors.New("signature is empty")
	}

	// Verify the signature using the initiator's public key
	if !ed25519.Verify(s.initiatorPubKey, msgBytes, signature) {
		return fmt.Errorf("invalid signature from initiator")
	}

	return nil
}

// AuthorizeInitiatorMessage verifies that a message has sufficient valid authorizer signatures
// according to the configured authorization policy. If authorization is disabled or the
// required threshold resolves to zero, this is a no-op.
func (s *fileStore) AuthorizeInitiatorMessage(operation string, msg types.InitiatorMessage) error {
	// If authorization is not enabled, allow
	if !viper.GetBool("authorization.enabled") {
		return nil
	}

	// Determine required threshold: operation-specific overrides default
	defaultThreshold := viper.GetInt("authorization.default_threshold")
	opPolicy := viper.GetStringMap("authorization.operation_policies." + operation)
	required := 0
	if val, ok := opPolicy["required_authorizers"]; ok {
		switch t := val.(type) {
		case int:
			required = t
		case int64:
			required = int(t)
		case float64:
			required = int(t)
		}
	}
	if required <= 0 {
		required = defaultThreshold
	}
	if required <= 0 {
		// No requirement; authorization effectively disabled
		return nil
	}

	// Build allowed authorizer ID set
	allowedIDs := map[string]struct{}{}
	if idsVal, ok := opPolicy["authorizer_ids"]; ok {
		switch ids := idsVal.(type) {
		case []interface{}:
			for _, idv := range ids {
				if sId, ok := idv.(string); ok && sId != "" {
					allowedIDs[sId] = struct{}{}
				}
			}
		case []string:
			for _, sId := range ids {
				if sId != "" {
					allowedIDs[sId] = struct{}{}
				}
			}
		}
	}
	// If no explicit allowed IDs configured, allow any configured authorizer
	if len(allowedIDs) == 0 {
		for id := range s.authorizerPubKeys {
			allowedIDs[id] = struct{}{}
		}
	}

	// Prepare payload
	msgBytes, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("authorization: failed to get raw payload: %w", err)
	}

	// Count valid signatures
	seen := map[string]struct{}{}
	validCount := 0
	for _, sig := range msg.AuthorizerSigs() {
		if sig.AuthorizerID == "" || len(sig.Signature) == 0 {
			continue
		}
		if _, dup := seen[sig.AuthorizerID]; dup {
			continue
		}
		if _, ok := allowedIDs[sig.AuthorizerID]; !ok {
			continue
		}
		pub, ok := s.authorizerPubKeys[sig.AuthorizerID]
		if !ok || len(pub) == 0 {
			continue
		}
		if ed25519.Verify(pub, msgBytes, sig.Signature) {
			seen[sig.AuthorizerID] = struct{}{}
			validCount++
		}
	}

	if validCount < required {
		return fmt.Errorf("authorization failed for %s: %d/%d valid authorizer signatures", operation, validCount, required)
	}

	return nil
}

func partyIDToNodeID(partyID *tss.PartyID) string {
	return strings.Split(string(partyID.KeyInt().Bytes()), ":")[0]
}
