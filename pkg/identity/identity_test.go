package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fystack/mpcium/pkg/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a temporary directory for tests
func createTempDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "identity_test_*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	return tempDir
}

// Helper function to create test identity files
func createTestIdentityFiles(t *testing.T, identityDir string) {
	// Create peers.json
	peers := map[string]string{
		"node1": "node1-id",
		"node2": "node2-id", 
	}
	peersData, err := json.Marshal(peers)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(identityDir, "..", "peers.json"), peersData, 0644)
	require.NoError(t, err)

	// Create identity files for each node
	for nodeName, nodeID := range peers {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		
		identity := NodeIdentity{
			NodeName:  nodeName,
			NodeID:    nodeID,
			PublicKey: hex.EncodeToString(pubKey),
			CreatedAt: "2024-01-01T00:00:00Z",
		}
		
		identityData, err := json.Marshal(identity)
		require.NoError(t, err)
		
		identityFile := filepath.Join(identityDir, fmt.Sprintf("%s_identity.json", nodeName))
		err = os.WriteFile(identityFile, identityData, 0644)
		require.NoError(t, err)
	}

	// Create private key for node1 (the test node)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateKeyFile := filepath.Join(identityDir, "node1_private.key")
	err = os.WriteFile(privateKeyFile, []byte(hex.EncodeToString(privateKey)), 0600)
	require.NoError(t, err)
}

// Helper function to setup viper configuration
func setupViperConfig(t *testing.T, config map[string]interface{}) {
	// Clear existing config
	for _, key := range viper.AllKeys() {
		viper.Set(key, nil)
	}
	
	// Set new config
	for key, value := range config {
		viper.Set(key, value)
	}
}

func TestNewFileStore_Success(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	// Change working directory to tempDir for peers.json
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Setup viper config
	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        false,
		"authorization.required_authorizers": 0,
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)
	assert.NotNil(t, store)
	
	// Test that we can get public keys
	pubKey, err := store.GetPublicKey("node1-id")
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestAuthorizationDisabled(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        false,
		"authorization.required_authorizers": 2,
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Authorization should pass when disabled
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.NoError(t, err)
}

func TestAuthorizationWithEd25519(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate authorizer keys
	authPubKey, authPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 1,
		"authorization.authorizer_public_keys": map[string]interface{}{
			"auth1": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey),
				"algorithm":  "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Get message raw bytes for signing
	msgBytes, err := msg.Raw()
	require.NoError(t, err)

	// Sign the message with authorizer key
	authSig := ed25519.Sign(authPrivKey, msgBytes)

	// Add authorizer signature
	msg.AuthorizerSignatures = []types.AuthorizerSignature{
		{
			AuthorizerID: "auth1",
			Signature:    authSig,
		},
	}

	// Authorization should pass with valid signature
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.NoError(t, err)
}

func TestAuthorizationInsufficientSignatures(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate authorizer keys
	authPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 2, // Require 2 signatures
		"authorization.authorizer_public_keys": map[string]interface{}{
			"auth1": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey),
				"algorithm":  "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message with no authorizer signatures
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Authorization should fail with insufficient signatures
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authorization failed for keygen: 0/2 valid authorizer signatures")
}

func TestAuthorizationInvalidSignature(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate authorizer keys
	authPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 1,
		"authorization.authorizer_public_keys": map[string]interface{}{
			"auth1": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey),
				"algorithm":  "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message with invalid signature
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
		AuthorizerSignatures: []types.AuthorizerSignature{
			{
				AuthorizerID: "auth1",
				Signature:    []byte("invalid-signature"),
			},
		},
	}

	// Authorization should fail with invalid signature
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authorization failed for keygen: 0/1 valid authorizer signatures")
}

func TestAuthorizationBackwardCompatibility(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate authorizer keys
	authPubKey, authPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Test old configuration format
	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 1,
		"authorization.authorizers": map[string]interface{}{
			"auth1": map[string]interface{}{
				"pubkey":    hex.EncodeToString(authPubKey),
				"algorithm": "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Get message raw bytes for signing
	msgBytes, err := msg.Raw()
	require.NoError(t, err)

	// Sign the message with authorizer key
	authSig := ed25519.Sign(authPrivKey, msgBytes)

	// Add authorizer signature
	msg.AuthorizerSignatures = []types.AuthorizerSignature{
		{
			AuthorizerID: "auth1",
			Signature:    authSig,
		},
	}

	// Authorization should pass with backward compatible config
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.NoError(t, err)
}

func TestVerifySignatureByAlgorithm_Ed25519(t *testing.T) {
	// Generate test key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(privKey, message)
	pubKeyHex := hex.EncodeToString(pubKey)

	// Test valid signature
	valid, err := verifySignatureByAlgorithm(pubKeyHex, "ed25519", message, signature)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Test invalid signature
	valid, err = verifySignatureByAlgorithm(pubKeyHex, "ed25519", message, []byte("invalid"))
	assert.NoError(t, err)
	assert.False(t, valid)

	// Test invalid public key
	valid, err = verifySignatureByAlgorithm("invalid-hex", "ed25519", message, signature)
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestVerifySignatureByAlgorithm_UnsupportedAlgorithm(t *testing.T) {
	valid, err := verifySignatureByAlgorithm("deadbeef", "unknown", []byte("message"), []byte("signature"))
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "unsupported signature algorithm: unknown")
}

func TestAuthorizationMultipleAuthorizers(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate multiple authorizer keys
	authPubKey1, authPrivKey1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authPubKey2, authPrivKey2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 2,
		"authorization.authorizer_public_keys": map[string]interface{}{
			"auth1": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey1),
				"algorithm":  "ed25519",
			},
			"auth2": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey2),
				"algorithm":  "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Get message raw bytes for signing
	msgBytes, err := msg.Raw()
	require.NoError(t, err)

	// Sign the message with both authorizer keys
	authSig1 := ed25519.Sign(authPrivKey1, msgBytes)
	authSig2 := ed25519.Sign(authPrivKey2, msgBytes)

	// Add both authorizer signatures
	msg.AuthorizerSignatures = []types.AuthorizerSignature{
		{
			AuthorizerID: "auth1",
			Signature:    authSig1,
		},
		{
			AuthorizerID: "auth2",
			Signature:    authSig2,
		},
	}

	// Authorization should pass with both signatures
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.NoError(t, err)
}

func TestAuthorizationDuplicateSignatures(t *testing.T) {
	tempDir := createTempDir(t)
	identityDir := filepath.Join(tempDir, "identities")
	err := os.MkdirAll(identityDir, 0750)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)

	createTestIdentityFiles(t, identityDir)

	// Generate authorizer keys
	authPubKey, authPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	setupViperConfig(t, map[string]interface{}{
		"event_initiator_pubkey":       "deadbeefcafebabe",
		"authorization.enabled":        true,
		"authorization.required_authorizers": 2,
		"authorization.authorizer_public_keys": map[string]interface{}{
			"auth1": map[string]interface{}{
				"public_key": hex.EncodeToString(authPubKey),
				"algorithm":  "ed25519",
			},
		},
	})

	store, err := NewFileStore(identityDir, "node1", false)
	require.NoError(t, err)

	// Create a test message
	msg := &types.GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: []byte("test-signature"),
	}

	// Get message raw bytes for signing
	msgBytes, err := msg.Raw()
	require.NoError(t, err)

	// Sign the message with authorizer key
	authSig := ed25519.Sign(authPrivKey, msgBytes)

	// Add duplicate authorizer signatures (should only count once)
	msg.AuthorizerSignatures = []types.AuthorizerSignature{
		{
			AuthorizerID: "auth1",
			Signature:    authSig,
		},
		{
			AuthorizerID: "auth1", // Duplicate
			Signature:    authSig,
		},
	}

	// Authorization should fail - only 1 unique signature, need 2
	err = store.AuthorizeInitiatorMessage("keygen", msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authorization failed for keygen: 1/2 valid authorizer signatures")
}
