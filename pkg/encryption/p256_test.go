package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// ----------------------
// Helper functions
// ----------------------

func mustGenerateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}
	return key
}

func mustMarshalToDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	return der
}

func mustParsePrivateKey(t *testing.T, data []byte) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ParseP256PrivateKey(data)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
	return key
}

func mustParseHexPrivateKey(t *testing.T, hexKey string) *ecdsa.PrivateKey {
	t.Helper()
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}
	return mustParsePrivateKey(t, keyBytes)
}

func mustSign(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()
	sig, err := SignWithP256(key, data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Signature is empty")
	}
	return sig
}

func mustVerify(t *testing.T, pub *ecdsa.PublicKey, data, sig []byte) {
	t.Helper()
	if err := VerifyP256Signature(pub, data, sig); err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

// ----------------------
// Actual tests
// ----------------------

func TestGenerateP256Keys(t *testing.T) {
	keyData, err := GenerateP256Keys()
	if err != nil {
		t.Fatalf("Failed to generate P256 keys: %v", err)
	}

	if _, err := hex.DecodeString(keyData.PublicKeyHex); err != nil {
		t.Errorf("Public key is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(keyData.PrivateKeyHex); err != nil {
		t.Errorf("Private key is not valid hex: %v", err)
	}

	privateKey := mustParsePrivateKey(t, []byte(keyData.PrivateKeyHex))
	if privateKey.Curve != elliptic.P256() {
		t.Error("Generated key is not P256 curve")
	}
}

func TestParseP256PrivateKey_DER(t *testing.T) {
	original := mustGenerateP256Key(t)
	der := mustMarshalToDER(t, original)
	parsed := mustParsePrivateKey(t, der)

	if !original.Equal(parsed) {
		t.Error("Parsed key is not equal to original key")
	}
}

func TestParseP256PrivateKey_Hex(t *testing.T) {
	original := mustGenerateP256Key(t)
	der := mustMarshalToDER(t, original)
	hexStr := hex.EncodeToString(der)

	parsed := mustParsePrivateKey(t, []byte(hexStr))
	if !original.Equal(parsed) {
		t.Error("Parsed key is not equal to original key")
	}
}

func TestParseP256PrivateKey_InvalidInput(t *testing.T) {
	cases := [][]byte{
		[]byte("invalid-hex"),
		{},
		func() []byte {
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				t.Fatalf("Failed to generate random bytes: %v", err)
			}
			return b
		}(),
	}

	for _, in := range cases {
		if _, err := ParseP256PrivateKey(in); err == nil {
			t.Errorf("Expected error for input %q", in)
		}
	}
}

func TestSignWithP256(t *testing.T) {
	key := mustGenerateP256Key(t)
	data := []byte("Hello, P256 signing!")
	sig := mustSign(t, key, data)

	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], sig) {
		t.Error("Generated signature is invalid")
	}
}

func TestSignWithP256_InvalidKey(t *testing.T) {
	if _, err := SignWithP256(nil, []byte("test")); err == nil {
		t.Error("Expected error for nil private key")
	}

	invalidKey := &ecdsa.PrivateKey{}
	_, err := SignWithP256(invalidKey, []byte("test"))
	if err == nil || err.Error() != "invalid private key: curve is nil" {
		t.Errorf("Expected specific error, got: %v", err)
	}
}

func TestSignWithP256_EmptyData(t *testing.T) {
	key := mustGenerateP256Key(t)
	mustSign(t, key, []byte{})
}

func TestParseP256PrivateKey_With0xPrefix(t *testing.T) {
	original := mustGenerateP256Key(t)
	der := mustMarshalToDER(t, original)
	hexStr := "0x" + hex.EncodeToString(der)

	parsed := mustParsePrivateKey(t, []byte(hexStr))
	if !original.Equal(parsed) {
		t.Error("Parsed key is not equal to original key")
	}
}

func TestSignAndVerifyWithSpecificKey(t *testing.T) {
	const privHex = "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"
	key := mustParseHexPrivateKey(t, privHex)

	data := []byte("test-wallet-p256")
	sig := mustSign(t, key, data)
	mustVerify(t, &key.PublicKey, data, sig)
}

func TestWalletIDSigningFlow(t *testing.T) {
	const privHex = "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"
	key := mustParseHexPrivateKey(t, privHex)

	for _, walletID := range []string{"test-wallet-p256", "aa7a8764-0899-45ad-9017-ec5a0ec5bfff", "another-test-wallet", "wallet-123"} {
		t.Run(walletID, func(t *testing.T) {
			data := []byte(walletID)
			sig := mustSign(t, key, data)
			mustVerify(t, &key.PublicKey, data, sig)
		})
	}
}

func TestParseP256PublicKeyFromHexAndBase64(t *testing.T) {
	keyData, err := GenerateP256Keys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Hex case
	pubKey, err := ParseP256PublicKeyFromHex(keyData.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to parse public key from hex: %v", err)
	}
	if pubKey.Curve != elliptic.P256() {
		t.Errorf("Expected P-256 curve, got %s", pubKey.Curve.Params().Name)
	}

	// With "0x" prefix
	pubKey2, err := ParseP256PublicKeyFromHex("0x" + keyData.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to parse public key with 0x prefix: %v", err)
	}
	if !pubKey.Equal(pubKey2) {
		t.Error("Public key mismatch with 0x prefix")
	}

	// Base64 case
	pubBytes, _ := hex.DecodeString(keyData.PublicKeyHex)
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	pubKey3, err := ParseP256PublicKeyFromBase64(pubB64)
	if err != nil {
		t.Fatalf("Failed to parse public key from base64: %v", err)
	}
	if !pubKey.Equal(pubKey3) {
		t.Error("Public key mismatch with base64 parsing")
	}
}

func TestValidateP256PublicKey(t *testing.T) {
	privKey := mustGenerateP256Key(t)
	pubKey := &privKey.PublicKey

	// Valid case
	if err := ValidateP256PublicKey(pubKey); err != nil {
		t.Errorf("Unexpected error for valid key: %v", err)
	}

	// Nil key
	if err := ValidateP256PublicKey(nil); err == nil {
		t.Error("Expected error for nil public key")
	}

	// Nil curve
	badKey := &ecdsa.PublicKey{}
	if err := ValidateP256PublicKey(badKey); err == nil {
		t.Error("Expected error for nil curve")
	}

	// Wrong curve
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := ValidateP256PublicKey(&otherPriv.PublicKey); err == nil {
		t.Error("Expected error for non-P256 curve")
	}
}

func TestVerifyP256Signature_InvalidCases(t *testing.T) {
	privKey := mustGenerateP256Key(t)
	data := []byte("verify test")
	sig := mustSign(t, privKey, data)

	// Nil public key
	if err := VerifyP256Signature(nil, data, sig); err == nil {
		t.Error("Expected error for nil public key")
	}

	// Wrong curve
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := VerifyP256Signature(&otherPriv.PublicKey, data, sig); err == nil {
		t.Error("Expected error for wrong curve")
	}

	// Empty signature
	if err := VerifyP256Signature(&privKey.PublicKey, data, []byte{}); err == nil {
		t.Error("Expected error for empty signature")
	}

	// Tampered signature
	tampered := append([]byte{}, sig...)
	tampered[len(tampered)-1] ^= 0xFF
	if err := VerifyP256Signature(&privKey.PublicKey, data, tampered); err == nil {
		t.Error("Expected error for tampered signature")
	}
}

func TestParseP256PublicKeyFromBytes_Invalid(t *testing.T) {
	// Random bytes that are not a public key
	randomBytes := make([]byte, 64)
	_, err := rand.Read(randomBytes)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	if _, err := ParseP256PublicKeyFromBytes(randomBytes); err == nil {
		t.Error("Expected error for invalid public key bytes")
	}
}
