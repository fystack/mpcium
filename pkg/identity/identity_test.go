package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
)

// Mock InitiatorMessage for testing
type mockInitiatorMessage struct {
	raw                  []byte
	sig                  []byte
	initiatorID          string
	authorizerSignatures []types.AuthorizerSignature
}

func (m *mockInitiatorMessage) Raw() ([]byte, error) {
	return m.raw, nil
}

func (m *mockInitiatorMessage) Sig() []byte {
	return m.sig
}

func (m *mockInitiatorMessage) InitiatorID() string {
	return m.initiatorID
}

func (m *mockInitiatorMessage) GetAuthorizerSignatures() []types.AuthorizerSignature {
	return m.authorizerSignatures
}

// Test helper functions
func generateTestEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, string) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubKeyHex := hex.EncodeToString(pubKey)
	return pubKey, privKey, pubKeyHex
}

func generateTestP256Key() (*ecdsa.PublicKey, *ecdsa.PrivateKey, string, error) {
	keyData, err := encryption.GenerateP256Keys()
	if err != nil {
		return nil, nil, "", err
	}

	privKeyBytes, err := hex.DecodeString(keyData.PrivateKeyHex)
	if err != nil {
		return nil, nil, "", err
	}

	privKey, err := encryption.ParseP256PrivateKey(privKeyBytes)
	if err != nil {
		return nil, nil, "", err
	}

	return &privKey.PublicKey, privKey, keyData.PublicKeyHex, nil
}

func createTestStore(authEnabled bool, authorizerKeys map[AuthorizerID]AuthorizerPublicKey) *fileStore {
	cachedKeys := make(map[AuthorizerID]any)

	if authEnabled {
		for id, keyMeta := range authorizerKeys {
			switch keyMeta.Algorithm {
			case AlgorithmEd25519:
				pubKeyBytes, err := encryption.ParseEd25519PublicKeyFromHex(keyMeta.PublicKey)
				if err != nil {
					panic(err)
				}
				cachedKeys[id] = ed25519.PublicKey(pubKeyBytes)

			case AlgorithmP256:
				pubKey, err := encryption.ParseP256PublicKeyFromHex(keyMeta.PublicKey)
				if err != nil {
					panic(err)
				}
				cachedKeys[id] = pubKey
			}
		}
	}

	return &fileStore{
		authConfig: AuthorizationConfig{
			Enabled:              authEnabled,
			RequiredAuthorizers:  []AuthorizerID{},
			AuthorizerPublicKeys: authorizerKeys,
		},
		cachedAuthorizerKeys: cachedKeys,
	}
}

// TestAuthorizeInitiatorMessage_Disabled tests authorization when it's disabled
func TestAuthorizeInitiatorMessage_Disabled(t *testing.T) {
	store := createTestStore(false, nil)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("fake signature"),
		initiatorID: "test-id",
		authorizerSignatures: []types.AuthorizerSignature{
			{AuthorizerID: "auth1", Signature: []byte("fake sig")},
		},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() with disabled auth should return nil, got error: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_NoSignatures tests when there are no authorizer signatures
func TestAuthorizeInitiatorMessage_NoSignatures(t *testing.T) {
	_, _, pubKeyHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:                  []byte("test message"),
		sig:                  []byte("fake signature"),
		initiatorID:          "test-id",
		authorizerSignatures: []types.AuthorizerSignature{},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() with no signatures should return nil, got error: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_ValidEd25519 tests valid Ed25519 authorizer signatures
func TestAuthorizeInitiatorMessage_ValidEd25519(t *testing.T) {
	// Generate authorizer keys
	auth1Pub, auth1Priv, auth1PubHex := generateTestEd25519Key()
	auth2Pub, auth2Priv, auth2PubHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth1PubHex,
			Algorithm: AlgorithmEd25519,
		},
		"auth2": {
			PublicKey: auth2PubHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	// Create test message
	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
	}

	// Compose the authorizer raw data
	authorizerRaw, err := types.ComposeAuthorizerRaw(msg)
	if err != nil {
		t.Fatalf("Failed to compose authorizer raw: %v", err)
	}

	// Sign with both authorizers
	auth1Sig := ed25519.Sign(auth1Priv, authorizerRaw)
	auth2Sig := ed25519.Sign(auth2Priv, authorizerRaw)

	msg.authorizerSignatures = []types.AuthorizerSignature{
		{AuthorizerID: "auth1", Signature: auth1Sig},
		{AuthorizerID: "auth2", Signature: auth2Sig},
	}

	err = store.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() with valid Ed25519 signatures failed: %v", err)
	}

	// Verify the keys are still valid
	if !ed25519.Verify(auth1Pub, authorizerRaw, auth1Sig) {
		t.Error("Auth1 signature verification failed")
	}
	if !ed25519.Verify(auth2Pub, authorizerRaw, auth2Sig) {
		t.Error("Auth2 signature verification failed")
	}
}

// TestAuthorizeInitiatorMessage_ValidP256 tests valid P256 authorizer signatures
func TestAuthorizeInitiatorMessage_ValidP256(t *testing.T) {
	// Generate P256 authorizer keys
	auth1Pub, auth1Priv, auth1PubHex, err := generateTestP256Key()
	if err != nil {
		t.Fatalf("Failed to generate P256 key for auth1: %v", err)
	}

	auth2Pub, auth2Priv, auth2PubHex, err := generateTestP256Key()
	if err != nil {
		t.Fatalf("Failed to generate P256 key for auth2: %v", err)
	}

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth1PubHex,
			Algorithm: AlgorithmP256,
		},
		"auth2": {
			PublicKey: auth2PubHex,
			Algorithm: AlgorithmP256,
		},
	}

	store := createTestStore(true, authorizerKeys)

	// Create test message
	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
	}

	// Compose the authorizer raw data
	authorizerRaw, err := types.ComposeAuthorizerRaw(msg)
	if err != nil {
		t.Fatalf("Failed to compose authorizer raw: %v", err)
	}

	// Sign with both P256 authorizers
	auth1Sig, err := encryption.SignWithP256(auth1Priv, authorizerRaw)
	if err != nil {
		t.Fatalf("Failed to sign with auth1: %v", err)
	}

	auth2Sig, err := encryption.SignWithP256(auth2Priv, authorizerRaw)
	if err != nil {
		t.Fatalf("Failed to sign with auth2: %v", err)
	}

	msg.authorizerSignatures = []types.AuthorizerSignature{
		{AuthorizerID: "auth1", Signature: auth1Sig},
		{AuthorizerID: "auth2", Signature: auth2Sig},
	}

	err = store.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() with valid P256 signatures failed: %v", err)
	}

	// Verify the signatures are still valid
	if err := encryption.VerifyP256Signature(auth1Pub, authorizerRaw, auth1Sig); err != nil {
		t.Errorf("Auth1 P256 signature verification failed: %v", err)
	}
	if err := encryption.VerifyP256Signature(auth2Pub, authorizerRaw, auth2Sig); err != nil {
		t.Errorf("Auth2 P256 signature verification failed: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_MixedAlgorithms tests mixed Ed25519 and P256 signatures
func TestAuthorizeInitiatorMessage_MixedAlgorithms(t *testing.T) {
	// Generate Ed25519 key for auth1
	_, auth1Ed25519Priv, auth1Ed25519PubHex := generateTestEd25519Key()

	// Generate P256 key for auth2
	_, auth2P256Priv, auth2P256PubHex, err := generateTestP256Key()
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth1Ed25519PubHex,
			Algorithm: AlgorithmEd25519,
		},
		"auth2": {
			PublicKey: auth2P256PubHex,
			Algorithm: AlgorithmP256,
		},
	}

	store := createTestStore(true, authorizerKeys)

	// Create test message
	msg := &mockInitiatorMessage{
		raw:         []byte("test message with mixed algorithms"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-456",
	}

	// Compose the authorizer raw data
	authorizerRaw, err := types.ComposeAuthorizerRaw(msg)
	if err != nil {
		t.Fatalf("Failed to compose authorizer raw: %v", err)
	}

	// Sign with Ed25519 authorizer
	auth1Sig := ed25519.Sign(auth1Ed25519Priv, authorizerRaw)

	// Sign with P256 authorizer
	auth2Sig, err := encryption.SignWithP256(auth2P256Priv, authorizerRaw)
	if err != nil {
		t.Fatalf("Failed to sign with P256: %v", err)
	}

	msg.authorizerSignatures = []types.AuthorizerSignature{
		{AuthorizerID: "auth1", Signature: auth1Sig},
		{AuthorizerID: "auth2", Signature: auth2Sig},
	}

	err = store.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() with mixed algorithms failed: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_InvalidSignature tests invalid signatures
func TestAuthorizeInitiatorMessage_InvalidSignature(t *testing.T) {
	_, _, authPubHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: authPubHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
		authorizerSignatures: []types.AuthorizerSignature{
			{AuthorizerID: "auth1", Signature: []byte("invalid signature")},
		},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail with invalid signature")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("Expected error to contain 'verification failed', got: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_UnknownAuthorizer tests unknown authorizer ID
func TestAuthorizeInitiatorMessage_UnknownAuthorizer(t *testing.T) {
	_, _, authPubHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: authPubHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
		authorizerSignatures: []types.AuthorizerSignature{
			{AuthorizerID: "unknown-auth", Signature: []byte("some signature")},
		},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail with unknown authorizer")
	}
	if !strings.Contains(err.Error(), "not found in cache") {
		t.Errorf("Expected error to contain 'not found in cache', got: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_WrongKeyForSignature tests signature signed with wrong key
func TestAuthorizeInitiatorMessage_WrongKeyForSignature(t *testing.T) {
	// Create two different key pairs
	_, auth1Priv, auth1PubHex := generateTestEd25519Key()
	_, _, auth2PubHex := generateTestEd25519Key() // Different key

	// Configure store with auth2's public key but sign with auth1's private key
	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth2PubHex, // Using auth2's public key
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
	}

	authorizerRaw, err := types.ComposeAuthorizerRaw(msg)
	if err != nil {
		t.Fatalf("Failed to compose authorizer raw: %v", err)
	}

	// Sign with auth1's private key
	wrongSig := ed25519.Sign(auth1Priv, authorizerRaw)

	msg.authorizerSignatures = []types.AuthorizerSignature{
		{AuthorizerID: "auth1", Signature: wrongSig},
	}

	err = store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail when signature doesn't match public key")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("Expected error to contain 'verification failed', got: %v", err)
	}

	// Also test with valid key to ensure our test setup is correct
	authorizerKeys2 := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth1PubHex, // Using correct public key
			Algorithm: AlgorithmEd25519,
		},
	}
	store2 := createTestStore(true, authorizerKeys2)
	err = store2.AuthorizeInitiatorMessage(msg)
	if err != nil {
		t.Errorf("AuthorizeInitiatorMessage() should succeed with correct key: %v", err)
	}
}

// TestVerifyAuthorizerSignature_Ed25519 tests the verifyAuthorizerSignature helper with Ed25519
func TestVerifyAuthorizerSignature_Ed25519(t *testing.T) {
	_, privKey, pubKeyHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	rawData := []byte("test data for signing")
	validSig := ed25519.Sign(privKey, rawData)

	tests := []struct {
		name      string
		raw       []byte
		sig       types.AuthorizerSignature
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid signature",
			raw:  rawData,
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    validSig,
			},
			wantError: false,
		},
		{
			name: "invalid signature",
			raw:  rawData,
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    []byte("invalid signature"),
			},
			wantError: true,
			errorMsg:  "verification failed",
		},
		{
			name: "unknown authorizer",
			raw:  rawData,
			sig: types.AuthorizerSignature{
				AuthorizerID: "unknown",
				Signature:    validSig,
			},
			wantError: true,
			errorMsg:  "not found in cache",
		},
		{
			name: "tampered data",
			raw:  []byte("different data"),
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    validSig,
			},
			wantError: true,
			errorMsg:  "verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.verifyAuthorizerSignature(tt.raw, tt.sig)

			if tt.wantError {
				if err == nil {
					t.Error("verifyAuthorizerSignature() expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("verifyAuthorizerSignature() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("verifyAuthorizerSignature() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestVerifyAuthorizerSignature_P256 tests the verifyAuthorizerSignature helper with P256
func TestVerifyAuthorizerSignature_P256(t *testing.T) {
	_, privKey, pubKeyHex, err := generateTestP256Key()
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmP256,
		},
	}

	store := createTestStore(true, authorizerKeys)

	rawData := []byte("test data for P256 signing")
	validSig, err := encryption.SignWithP256(privKey, rawData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	tests := []struct {
		name      string
		raw       []byte
		sig       types.AuthorizerSignature
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid P256 signature",
			raw:  rawData,
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    validSig,
			},
			wantError: false,
		},
		{
			name: "invalid P256 signature",
			raw:  rawData,
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    []byte("invalid signature"),
			},
			wantError: true,
			errorMsg:  "verification failed",
		},
		{
			name: "tampered P256 data",
			raw:  []byte("different data"),
			sig: types.AuthorizerSignature{
				AuthorizerID: "auth1",
				Signature:    validSig,
			},
			wantError: true,
			errorMsg:  "verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.verifyAuthorizerSignature(tt.raw, tt.sig)

			if tt.wantError {
				if err == nil {
					t.Error("verifyAuthorizerSignature() expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("verifyAuthorizerSignature() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("verifyAuthorizerSignature() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestGetAuthorizerPublicKey tests the getAuthorizerPublicKey helper
func TestGetAuthorizerPublicKey(t *testing.T) {
	_, _, pubKeyHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	tests := []struct {
		name         string
		authorizerID string
		wantError    bool
		errorMsg     string
	}{
		{
			name:         "existing authorizer",
			authorizerID: "auth1",
			wantError:    false,
		},
		{
			name:         "non-existent authorizer",
			authorizerID: "unknown",
			wantError:    true,
			errorMsg:     "unknown authorizer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := store.getAuthorizerPublicKey(tt.authorizerID)

			if tt.wantError {
				if err == nil {
					t.Error("getAuthorizerPublicKey() expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("getAuthorizerPublicKey() error = %v, want error containing %q", err, tt.errorMsg)
				}
				if pubKey != nil {
					t.Error("getAuthorizerPublicKey() expected nil public key on error")
				}
			} else {
				if err != nil {
					t.Errorf("getAuthorizerPublicKey() unexpected error = %v", err)
				}
				if pubKey == nil {
					t.Error("getAuthorizerPublicKey() expected non-nil public key")
				} else if pubKey.PublicKey != pubKeyHex {
					t.Errorf("getAuthorizerPublicKey() public key = %v, want %v", pubKey.PublicKey, pubKeyHex)
				}
			}
		})
	}
}

// TestAuthorizeInitiatorMessage_MultipleAuthorizersPartialFailure tests failure when one of multiple signatures is invalid
func TestAuthorizeInitiatorMessage_MultipleAuthorizersPartialFailure(t *testing.T) {
	// Generate two Ed25519 keys
	_, auth1Priv, auth1PubHex := generateTestEd25519Key()
	_, _, auth2PubHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: auth1PubHex,
			Algorithm: AlgorithmEd25519,
		},
		"auth2": {
			PublicKey: auth2PubHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
	}

	authorizerRaw, err := types.ComposeAuthorizerRaw(msg)
	if err != nil {
		t.Fatalf("Failed to compose authorizer raw: %v", err)
	}

	// Create one valid signature and one invalid
	validSig := ed25519.Sign(auth1Priv, authorizerRaw)
	invalidSig := []byte("invalid signature for auth2")

	msg.authorizerSignatures = []types.AuthorizerSignature{
		{AuthorizerID: "auth1", Signature: validSig},
		{AuthorizerID: "auth2", Signature: invalidSig},
	}

	err = store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail when one of multiple signatures is invalid")
	}
	if !strings.Contains(err.Error(), "auth2") {
		t.Errorf("Expected error to mention 'auth2', got: %v", err)
	}
}

// TestAuthorizeInitiatorMessage_EmptySignature tests behavior with empty signature bytes
func TestAuthorizeInitiatorMessage_EmptySignature(t *testing.T) {
	_, _, pubKeyHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
		authorizerSignatures: []types.AuthorizerSignature{
			{AuthorizerID: "auth1", Signature: []byte{}},
		},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail with empty signature")
	}
}

// TestAuthorizeInitiatorMessage_NilSignature tests behavior with nil signature
func TestAuthorizeInitiatorMessage_NilSignature(t *testing.T) {
	_, _, pubKeyHex := generateTestEd25519Key()

	authorizerKeys := map[AuthorizerID]AuthorizerPublicKey{
		"auth1": {
			PublicKey: pubKeyHex,
			Algorithm: AlgorithmEd25519,
		},
	}

	store := createTestStore(true, authorizerKeys)

	msg := &mockInitiatorMessage{
		raw:         []byte("test message"),
		sig:         []byte("initiator signature"),
		initiatorID: "wallet-123",
		authorizerSignatures: []types.AuthorizerSignature{
			{AuthorizerID: "auth1", Signature: nil},
		},
	}

	err := store.AuthorizeInitiatorMessage(msg)
	if err == nil {
		t.Error("AuthorizeInitiatorMessage() should fail with nil signature")
	}
}
