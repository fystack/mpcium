package encoding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeS256PubKey(t *testing.T) {
	pubKey := &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)
	require.Len(t, encoded, 64)

	expectedX := pubKey.X.FillBytes(make([]byte, 32))
	expectedY := pubKey.Y.FillBytes(make([]byte, 32))
	expected := append(expectedX, expectedY...)
	assert.Equal(t, expected, encoded)
}

func TestEncodeS256PubKey_WithValidKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privateKey.PublicKey

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)
	require.Len(t, encoded, 64)

	expectedX := pubKey.X.FillBytes(make([]byte, 32))
	expectedY := pubKey.Y.FillBytes(make([]byte, 32))
	expected := append(expectedX, expectedY...)
	assert.Equal(t, expected, encoded)
}

func TestEncodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair using the correct API
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := privateKey.PubKey()

	// Test encoding
	encoded, err := EncodeEDDSAPubKey(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// EdDSA compressed public key should be 32 bytes (not 33 as initially assumed)
	assert.Equal(t, 32, len(encoded))
}

func TestDecodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	originalPubKey := privateKey.PubKey()

	// Encode the public key
	encoded, err := EncodeEDDSAPubKey(originalPubKey)
	require.NoError(t, err)

	// Decode the public key
	decodedPubKey, err := DecodeEDDSAPubKey(encoded)
	require.NoError(t, err)
	assert.NotNil(t, decodedPubKey)

	// Verify the decoded key matches the original by comparing serialized forms
	originalSerialized := originalPubKey.SerializeCompressed()
	decodedSerialized := decodedPubKey.SerializeCompressed()
	assert.Equal(t, originalSerialized, decodedSerialized)
}

func TestDecodeEDDSAPubKey_InvalidData(t *testing.T) {
	// Test with invalid data
	invalidData := []byte("invalid key data")

	_, err := DecodeEDDSAPubKey(invalidData)
	assert.Error(t, err)
}

func TestDecodeEDDSAPubKey_EmptyData(t *testing.T) {
	// Test with empty data
	emptyData := []byte{}

	_, err := DecodeEDDSAPubKey(emptyData)
	assert.Error(t, err)
}

func TestEncodeDecodeEDDSA_RoundTrip(t *testing.T) {
	// Test multiple round trips to ensure consistency
	for i := 0; i < 10; i++ {
		// Generate a new key pair
		privateKey, err := edwards.GeneratePrivateKey()
		require.NoError(t, err)

		originalPubKey := privateKey.PubKey()

		// Encode
		encoded, err := EncodeEDDSAPubKey(originalPubKey)
		require.NoError(t, err)

		// Decode
		decodedPubKey, err := DecodeEDDSAPubKey(encoded)
		require.NoError(t, err)

		// Verify they match by comparing serialized forms
		originalSerialized := originalPubKey.SerializeCompressed()
		decodedSerialized := decodedPubKey.SerializeCompressed()
		assert.Equal(t, originalSerialized, decodedSerialized, "Round trip %d failed", i)
	}
}

func TestEncodeS256PubKey_NilPublicKey(t *testing.T) {
	_, err := EncodeS256PubKey(nil)
	require.EqualError(t, err, "public key is nil")
}

func TestEncodeS256PubKey_UnsupportedCurve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = EncodeS256PubKey(&privateKey.PublicKey)
	require.ErrorContains(t, err, "unsupported curve")
}

func TestEncodeS256PubKey_CoordinateTooLarge(t *testing.T) {
	pubKey := &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     new(big.Int).Lsh(big.NewInt(1), 256),
		Y:     big.NewInt(0),
	}

	_, err := EncodeS256PubKey(pubKey)
	require.EqualError(t, err, "coordinate length exceeds 32 bytes")
}
