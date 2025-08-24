package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type KeyData struct {
	PublicKeyHex  string
	PrivateKeyHex string
}

// ParseP256PrivateKey parses a P256 private key from either DER or hex format
func ParseP256PrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	// Try to parse as DER first
	if key, err := x509.ParsePKCS8PrivateKey(keyData); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
	}

	// Try to parse as EC private key
	if key, err := x509.ParseECPrivateKey(keyData); err == nil {
		return key, nil
	}

	// Try to parse as hex string
	keyStr := strings.TrimSpace(string(keyData))
	keyStr = strings.TrimPrefix(keyStr, "0x")

	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Try to parse as DER again with decoded hex
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
	}

	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse P256 private key from DER or hex format")
}

// SignWithP256 signs data using a P256 private key
func SignWithP256(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("invalid private key: private key is nil")
	}

	if privateKey.Curve == nil {
		return nil, fmt.Errorf("invalid private key: curve is nil")
	}

	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

func GenerateP256Keys() (KeyData, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyData{}, err
	}

	// Convert private key to PEM format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return KeyData{}, err
	}

	// Convert public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyData{}, err
	}

	return KeyData{
		PublicKeyHex:  hex.EncodeToString(publicKeyBytes),
		PrivateKeyHex: hex.EncodeToString(privateKeyBytes),
	}, nil
}

// VerifyP256Signature verifies a P256 signature
func VerifyP256Signature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("public key is not on P-256 curve")
	}
	if len(signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	hash := sha256.Sum256(data)

	if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
func ParseP256PublicKeyFromBytes(keyBytes []byte) (*ecdsa.PublicKey, error) {
	// Try to parse as DER first
	if key, err := x509.ParsePKIXPublicKey(keyBytes); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
			if ecdsaKey.Curve == elliptic.P256() {
				return ecdsaKey, nil
			}
		}
	}

	// Try to parse as EC public key
	if key, err := x509.ParsePKIXPublicKey(keyBytes); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
			if ecdsaKey.Curve == elliptic.P256() {
				return ecdsaKey, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to parse P-256 public key from bytes")
}

// ParseP256PublicKeyFromHex parses a P-256 public key from hex string
func ParseP256PublicKeyFromHex(hexString string) (*ecdsa.PublicKey, error) {
	hexString = strings.TrimPrefix(hexString, "0x")
	keyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return ParseP256PublicKeyFromBytes(keyBytes)
}

// ParseP256PublicKeyFromBase64 parses a P-256 public key from base64 string
func ParseP256PublicKeyFromBase64(base64String string) (*ecdsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}

	return ParseP256PublicKeyFromBytes(keyBytes)
}

// ValidateP256PublicKey validates that a public key is P-256
func ValidateP256PublicKey(publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}
	if publicKey.Curve == nil {
		return fmt.Errorf("public key curve is nil")
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("public key is not P-256 curve (got: %s)", publicKey.Curve.Params().Name)
	}
	return nil
}
