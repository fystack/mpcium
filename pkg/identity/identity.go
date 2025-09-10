package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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

// AuthorizerInfo represents a single authorizer with their public key and algorithm
type AuthorizerInfo struct {
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"` // "ed25519" or "secp256k1"
}

// AuthorizationConfig holds the cached authorization configuration
type AuthorizationConfig struct {
	Enabled              bool
	RequiredAuthorizers  int
	AuthorizerPublicKeys map[string]AuthorizerInfo // key is authorizer ID
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

	// Cached authorizer information by authorizer ID
	authorizerInfo map[string]AuthorizerInfo

	// Cached authorization configuration
	authzConfig AuthorizationConfig
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
		identityDir:     identityDir,
		currentNodeName: nodeName,
		publicKeys:      make(map[string][]byte),
		privateKey:      privateKey,
		initiatorPubKey: initiatorPubKey,
		authorizerInfo:  make(map[string]AuthorizerInfo),
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

	// Load authorization configuration
	store.authzConfig = AuthorizationConfig{
		Enabled:              viper.GetBool("authorization.enabled"),
		RequiredAuthorizers:  viper.GetInt("authorization.required_authorizers"),
		AuthorizerPublicKeys: make(map[string]AuthorizerInfo),
	}

	// Load authorizer public keys
	authKeys := viper.GetStringMap("authorization.authorizer_public_keys")
	for authID, authData := range authKeys {
		if authInfo, ok := authData.(map[string]interface{}); ok {
			info := AuthorizerInfo{
				Algorithm: "ed25519", // default algorithm
			}

			if pubKey, ok := authInfo["public_key"].(string); ok && pubKey != "" {
				info.PublicKey = pubKey
			}

			if algo, ok := authInfo["algorithm"].(string); ok && algo != "" {
				info.Algorithm = algo
			}

			if info.PublicKey != "" {
				store.authzConfig.AuthorizerPublicKeys[authID] = info
				store.authorizerInfo[authID] = info
			}
		}
	}

	// Load global authorizer configuration (backward compatibility)
	authzAuthorizers := viper.GetStringMap("authorization.authorizers")
	for id, v := range authzAuthorizers {
		// Skip if already loaded from operation-specific config
		if _, exists := store.authorizerInfo[id]; exists {
			continue
		}

		// v is expected to be a map with key "pubkey" and optional "algorithm"
		if entry, ok := v.(map[string]interface{}); ok {
			info := AuthorizerInfo{
				Algorithm: "ed25519", // default algorithm
			}

			if pubHexRaw, ok := entry["pubkey"]; ok {
				if pubHex, ok := pubHexRaw.(string); ok && pubHex != "" {
					info.PublicKey = pubHex
				}
			}

			if algoRaw, ok := entry["algorithm"]; ok {
				if algo, ok := algoRaw.(string); ok && algo != "" {
					info.Algorithm = algo
				}
			}

			if info.PublicKey != "" {
				store.authorizerInfo[id] = info
			} else {
				logger.Warn("Invalid or empty pubkey for authorizer", "authorizerID", id)
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
// The operation parameter is kept for logging and debugging purposes.
func (s *fileStore) AuthorizeInitiatorMessage(operation string, msg types.InitiatorMessage) error {
	// If authorization is not enabled, allow
	if !s.authzConfig.Enabled {
		return nil
	}

	// Get required threshold
	required := s.authzConfig.RequiredAuthorizers
	if required <= 0 {
		// No requirement; authorization effectively disabled
		return nil
	}

	// Use configured authorizers
	allowedAuthorizers := s.authzConfig.AuthorizerPublicKeys
	if len(allowedAuthorizers) == 0 {
		// Fallback to global authorizer info for backward compatibility
		allowedAuthorizers = s.authorizerInfo
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

		authInfo, ok := allowedAuthorizers[sig.AuthorizerID]
		if !ok || authInfo.PublicKey == "" {
			continue
		}

		// Verify signature using the appropriate algorithm
		valid, err := verifySignatureByAlgorithm(authInfo.PublicKey, authInfo.Algorithm, msgBytes, sig.Signature)
		if err != nil {
			logger.Warn("Failed to verify authorizer signature", "authorizerID", sig.AuthorizerID, "algorithm", authInfo.Algorithm, "error", err)
			continue
		}

		if valid {
			seen[sig.AuthorizerID] = struct{}{}
			validCount++
		}
	}

	if validCount < required {
		return fmt.Errorf("authorization failed for %s: %d/%d valid authorizer signatures", operation, validCount, required)
	}

	return nil
}

// verifySignatureByAlgorithm verifies a signature using the specified algorithm
func verifySignatureByAlgorithm(publicKeyHex, algorithm string, message, signature []byte) (bool, error) {
	switch algorithm {
	case "ed25519":
		pubKeyBytes, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			return false, fmt.Errorf("invalid ed25519 public key hex: %w", err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return false, fmt.Errorf("invalid ed25519 public key length: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
		}
		return ed25519.Verify(pubKeyBytes, message, signature), nil

	case "secp256k1", "p256":
		pubKeyBytes, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			return false, fmt.Errorf("invalid ecdsa public key hex: %w", err)
		}

		// Parse the public key
		var curve elliptic.Curve
		if algorithm == "secp256k1" {
			// For secp256k1, we'd need to import a secp256k1 library
			// For now, we'll use P256 as a placeholder
			curve = elliptic.P256()
		} else {
			curve = elliptic.P256()
		}

		// Assume uncompressed point format (0x04 + 32 bytes x + 32 bytes y)
		if len(pubKeyBytes) == 65 && pubKeyBytes[0] == 0x04 {
			x := new(big.Int).SetBytes(pubKeyBytes[1:33])
			y := new(big.Int).SetBytes(pubKeyBytes[33:65])
			_ = &ecdsa.PublicKey{Curve: curve, X: x, Y: y} // pubKey would be used for actual verification

			// Parse DER-encoded signature
			// This is a simplified implementation - in production you'd want proper ASN.1 parsing
			if len(signature) < 6 {
				return false, fmt.Errorf("signature too short")
			}

			// For now, return false - proper ECDSA signature verification would need more robust parsing
			logger.Warn("ECDSA signature verification not fully implemented", "algorithm", algorithm)
			return false, fmt.Errorf("ECDSA signature verification not fully implemented for %s", algorithm)
		} else {
			return false, fmt.Errorf("unsupported public key format for %s", algorithm)
		}

	default:
		return false, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

func partyIDToNodeID(partyID *tss.PartyID) string {
	return strings.Split(string(partyID.KeyInt().Bytes()), ":")[0]
}
