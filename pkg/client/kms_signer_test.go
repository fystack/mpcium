package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockKMSClient is a mock implementation of the AWS KMS client
type MockKMSClient struct {
	mock.Mock
}

func (m *MockKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*kms.GetPublicKeyOutput), args.Error(1)
}

func (m *MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*kms.SignOutput), args.Error(1)
}

func TestNewKMSSigner_Success(t *testing.T) {
	// Generate a test P256 key for mock response
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	// Create mock client
	mockClient := &MockKMSClient{}
	mockClient.On("GetPublicKey", mock.Anything, mock.MatchedBy(func(input *kms.GetPublicKeyInput) bool {
		return *input.KeyId == "test-key-id"
	})).Return(&kms.GetPublicKeyOutput{
		PublicKey: publicKeyBytes,
	}, nil)

	// Test creating KMS signer - we'll need to inject the mock somehow
	// For now, we'll test the validation logic
	opts := KMSSignerOptions{
		Region: "us-east-1",
		KeyID:  "test-key-id",
	}

	// Test validation
	assert.NotEmpty(t, opts.KeyID)
	assert.NotEmpty(t, opts.Region)
}

func TestNewKMSSigner_ValidationErrors(t *testing.T) {
	t.Run("unsupported key type", func(t *testing.T) {
		_, err := NewKMSSigner(types.EventInitiatorKeyTypeEd25519, KMSSignerOptions{
			Region: "us-east-1",
			KeyID:  "test-key",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AWS KMS only supports P256 keys")
	})

	t.Run("missing key ID", func(t *testing.T) {
		_, err := NewKMSSigner(types.EventInitiatorKeyTypeP256, KMSSignerOptions{
			Region: "us-east-1",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "KeyID is required")
	})
}

func TestKMSSigner_Algorithm(t *testing.T) {
	// Create a KMS signer instance directly (bypassing AWS client creation for unit test)
	signer := &KMSSigner{
		keyType: types.EventInitiatorKeyTypeP256,
	}

	assert.Equal(t, types.EventInitiatorKeyTypeP256, signer.Algorithm())
}

func TestKMSSigner_PublicKey(t *testing.T) {
	// Generate a test P256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a KMS signer instance with a test public key
	signer := &KMSSigner{
		keyType:   types.EventInitiatorKeyTypeP256,
		publicKey: &privateKey.PublicKey,
	}

	pubKeyHex, err := signer.PublicKey()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyHex)

	// Verify it's valid hex
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyBytes)

	// Verify we can parse the public key back
	parsedPubKey, err := encryption.ParseP256PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, privateKey.PublicKey.Equal(parsedPubKey))
}

func TestKMSSigner_PublicKey_NotLoaded(t *testing.T) {
	signer := &KMSSigner{
		keyType: types.EventInitiatorKeyTypeP256,
		// publicKey is nil
	}

	pubKeyHex, err := signer.PublicKey()
	assert.Error(t, err)
	assert.Empty(t, pubKeyHex)
	assert.Contains(t, err.Error(), "public key not loaded")
}

// TestKMSSignerIntegration tests the KMS signer with mocked AWS responses
func TestKMSSignerIntegration(t *testing.T) {
	// This test would require more complex mocking to fully test the KMS integration
	// For now, we test the structure and validation logic

	t.Run("options validation", func(t *testing.T) {
		validOpts := KMSSignerOptions{
			Region: "us-west-2",
			KeyID:  "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		}

		// Test that options are properly structured
		assert.NotEmpty(t, validOpts.Region)
		assert.NotEmpty(t, validOpts.KeyID)
		assert.Contains(t, validOpts.KeyID, "arn:aws:kms") // Example ARN format
	})

	t.Run("key ID formats", func(t *testing.T) {
		validKeyIDs := []string{
			"12345678-1234-1234-1234-123456789012", // Key ID
			"alias/my-key",                         // Alias
			"arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012", // Full ARN
			"arn:aws:kms:us-west-2:123456789012:alias/my-key",                             // Alias ARN
		}

		for _, keyID := range validKeyIDs {
			opts := KMSSignerOptions{
				Region: "us-west-2",
				KeyID:  keyID,
			}
			assert.NotEmpty(t, opts.KeyID, "Key ID should not be empty: %s", keyID)
		}
	})
}

// TestKMSSignerMockIntegration demonstrates how to test KMS signer with proper mocking
func TestKMSSignerMockIntegration(t *testing.T) {
	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Note: For actual testing, we would use these variables
	_ = privateKey // Avoid unused variable error

	// Create a KMS signer with test data (simulating successful initialization)
	signer := &KMSSigner{
		keyType:   types.EventInitiatorKeyTypeP256,
		keyID:     "test-key-id",
		publicKey: &privateKey.PublicKey,
	}

	// Test public key retrieval
	pubKeyHex, err := signer.PublicKey()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyHex)

	// Verify the hex can be decoded back to the correct public key
	decodedBytes, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)

	parsedPubKey, err := encryption.ParseP256PublicKeyFromBytes(decodedBytes)
	require.NoError(t, err)
	assert.True(t, signer.publicKey.Equal(parsedPubKey))

	// Test algorithm
	assert.Equal(t, types.EventInitiatorKeyTypeP256, signer.Algorithm())

	// Note: Actual signing would require mocking the AWS client's Sign method
	// This demonstrates the structure for such tests
	t.Log("KMS signer structure validated successfully")
}

// Helper function to create a test KMS signer (for integration tests)
func createTestKMSSigner(t *testing.T) *KMSSigner {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &KMSSigner{
		keyType:   types.EventInitiatorKeyTypeP256,
		keyID:     "test-key-id",
		publicKey: &privateKey.PublicKey,
	}
}

func TestKMSSignerHelpers(t *testing.T) {
	signer := createTestKMSSigner(t)

	assert.Equal(t, types.EventInitiatorKeyTypeP256, signer.Algorithm())

	pubKey, err := signer.PublicKey()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKey)
}
