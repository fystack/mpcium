package coordinator

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type Signer interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
}

type SessionEventVerifier interface {
	VerifySessionEvent(ctx context.Context, session *Session, event *sdkprotocol.SessionEvent) error
}

type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

func NewEd25519SignerFromHex(privateKeyHex string) (*Ed25519Signer, error) {
	raw, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode coordinator private key hex: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return &Ed25519Signer{privateKey: ed25519.PrivateKey(raw)}, nil
	case ed25519.SeedSize:
		return &Ed25519Signer{privateKey: ed25519.NewKeyFromSeed(raw)}, nil
	default:
		return nil, fmt.Errorf("invalid Ed25519 private key length %d", len(raw))
	}
}

func (s *Ed25519Signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	if len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	return ed25519.Sign(s.privateKey, data), nil
}

type Ed25519SessionEventVerifier struct{}

func (Ed25519SessionEventVerifier) VerifySessionEvent(_ context.Context, session *Session, event *sdkprotocol.SessionEvent) error {
	if session == nil || event == nil {
		return newCoordinatorError(ErrorCodeValidation, "invalid session event verification input")
	}
	pubKey, ok := session.ParticipantKeys[event.ParticipantID]
	if !ok || len(pubKey) == 0 {
		return newCoordinatorError(ErrorCodeUnauthorized, "unknown participant public key")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return newCoordinatorError(ErrorCodeValidation, "invalid participant public key length")
	}
	payload, err := sdkprotocol.SessionEventSigningBytes(event)
	if err != nil {
		return newCoordinatorError(ErrorCodeValidation, err.Error())
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), payload, event.Signature) {
		return newCoordinatorError(ErrorCodeUnauthorized, "invalid participant event signature")
	}
	return nil
}

func SignControl(ctx context.Context, signer Signer, control *sdkprotocol.ControlMessage) error {
	control.Signature = nil
	bytes, err := sdkprotocol.ControlSigningBytes(control)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, bytes)
	if err != nil {
		return fmt.Errorf("sign control: %w", err)
	}
	control.Signature = sig
	return nil
}
