package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
)

// KMSSigner implements the Signer interface for AWS KMS-based signing
type KMSSigner struct {
	keyType   types.EventInitiatorKeyType
	client    *kms.Client
	keyID     string
	publicKey *ecdsa.PublicKey
}

// KMSSignerOptions defines options for creating a KMSSigner
type KMSSignerOptions struct {
	Region          string // AWS region (e.g., "us-east-1", "us-west-2") - Required
	KeyID           string // AWS KMS key ID or ARN - Required
	EndpointURL     string // Custom endpoint URL (optional, for LocalStack/custom services)
	AccessKeyID     string // AWS access key ID (optional, for local/LocalStack only — recommended to leave empty in production to use the Default Credential Chain)
	SecretAccessKey string // AWS secret access key (optional, for local/LocalStack only — recommended to leave empty in production to use the Default Credential Chain)
}

// NewKMSSigner creates a new KMSSigner using AWS KMS
// Note: AWS KMS supports P256, not Ed25519
func NewKMSSigner(keyType types.EventInitiatorKeyType, opts KMSSignerOptions) (Signer, error) {
	// AWS KMS only supports P256 for ECDSA
	if keyType != types.EventInitiatorKeyTypeP256 {
		return nil, fmt.Errorf("AWS KMS only supports P256 keys, not %s", keyType)
	}

	// Validate required options
	if opts.KeyID == "" {
		return nil, fmt.Errorf("KeyID is required for KMS signer")
	}
	if opts.Region == "" {
		return nil, fmt.Errorf("Region is required for KMS signer")
	}

	// Create AWS config
	ctx := context.Background()
	var configOptions []func(*config.LoadOptions) error

	// Set region
	configOptions = append(configOptions, config.WithRegion(opts.Region))

	// Set custom credentials if provided
	if opts.AccessKeyID != "" && opts.SecretAccessKey != "" {
		credProvider := credentials.NewStaticCredentialsProvider(opts.AccessKeyID, opts.SecretAccessKey, "")
		configOptions = append(configOptions, config.WithCredentialsProvider(credProvider))
	}

	cfg, err := config.LoadDefaultConfig(ctx, configOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create KMS client with optional custom endpoint
	var clientOptions []func(*kms.Options)
	if opts.EndpointURL != "" {
		clientOptions = append(clientOptions, func(o *kms.Options) {
			o.BaseEndpoint = &opts.EndpointURL
		})
	}

	client := kms.NewFromConfig(cfg, clientOptions...)

	signer := &KMSSigner{
		keyType: keyType,
		client:  client,
		keyID:   opts.KeyID,
	}

	// Retrieve and cache the public key
	if err := signer.loadPublicKey(ctx); err != nil {
		return nil, fmt.Errorf("failed to load public key from KMS: %w", err)
	}

	return signer, nil
}

// loadPublicKey retrieves the public key from AWS KMS and caches it
func (k *KMSSigner) loadPublicKey(ctx context.Context) error {
	input := &kms.GetPublicKeyInput{
		KeyId: &k.keyID,
	}

	resp, err := k.client.GetPublicKey(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get public key from AWS KMS: %w", err)
	}

	// Parse DER encoded public key
	publicKeyInterface, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key from KMS response: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("KMS public key is not an ECDSA key")
	}

	// Validate it's P256
	if err := encryption.ValidateP256PublicKey(publicKey); err != nil {
		return fmt.Errorf("KMS public key is not a valid P256 key: %w", err)
	}

	k.publicKey = publicKey
	return nil
}

// Sign implements the Signer interface for KMSSigner
func (k *KMSSigner) Sign(data []byte) ([]byte, error) {
	ctx := context.Background()

	// Create the signing request
	input := &kms.SignInput{
		KeyId:            &k.keyID,
		Message:          data,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	// Call AWS KMS to sign the data
	resp, err := k.client.Sign(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with AWS KMS: %w", err)
	}

	return resp.Signature, nil
}

// Algorithm implements the Signer interface for KMSSigner
func (k *KMSSigner) Algorithm() types.EventInitiatorKeyType {
	return k.keyType
}

// PublicKey implements the Signer interface for KMSSigner
func (k *KMSSigner) PublicKey() (string, error) {
	if k.publicKey == nil {
		return "", fmt.Errorf("public key not loaded")
	}

	pubKeyBytes, err := encryption.MarshalP256PublicKey(k.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal P256 public key: %w", err)
	}

	return hex.EncodeToString(pubKeyBytes), nil
}
