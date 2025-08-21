package mpc

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"

	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"

	"encoding/json"

	"github.com/nats-io/nats.go"
)

const (
	ECDHExchangeTopic   = "ecdh:exchange"
	ECDHExchangeTimeout = 2 * time.Minute
)

type ECDHSession interface {
	ListenKeyExchange() error
	BroadcastPublicKey() error
	RemovePeer(peerID string)
	GetReadyPeersCount() int
	ErrChan() <-chan error
	Close() error
}

type ecdhSession struct {
	nodeID        string
	peerIDs       []string
	pubSub        messaging.PubSub
	ecdhSub       messaging.Subscription
	identityStore identity.Store
	privateKey    *ecdh.PrivateKey
	publicKey     *ecdh.PublicKey
	errCh         chan error
}

func NewECDHSession(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	identityStore identity.Store,
) *ecdhSession {
	return &ecdhSession{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		identityStore: identityStore,
		errCh:         make(chan error, 1),
	}
}

func (e *ecdhSession) RemovePeer(peerID string) {
	e.identityStore.RemoveSymmetricKey(peerID)
}

func (e *ecdhSession) GetReadyPeersCount() int {
	return e.identityStore.GetSymetricKeyCount()
}

func (e *ecdhSession) ErrChan() <-chan error {
	return e.errCh
}

func (e *ecdhSession) ListenKeyExchange() error {
	// Generate an ephemeral ECDH key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH key pair: %w", err)
	}

	e.privateKey = privateKey
	e.publicKey = privateKey.PublicKey()

	// Subscribe to ECDH broadcast
	sub, err := e.pubSub.Subscribe(ECDHExchangeTopic, func(natMsg *nats.Msg) {
		var ecdhMsg types.ECDHMessage
		if err := json.Unmarshal(natMsg.Data, &ecdhMsg); err != nil {
			return
		}

		if ecdhMsg.From == e.nodeID {
			return
		}

		//TODO: consider how to avoid replay attack
		if err := e.identityStore.VerifySignature(&ecdhMsg); err != nil {
			e.errCh <- err
			return
		}

		peerPublicKey, err := ecdh.X25519().NewPublicKey(ecdhMsg.PublicKey)
		if err != nil {
			e.errCh <- err
			return
		}
		sharedSecret, err := e.privateKey.ECDH(peerPublicKey)
		if err != nil {
			e.errCh <- err
			return
		}

		// Derive symmetric key using HKDF
		symmetricKey := e.deriveSymmetricKey(sharedSecret, ecdhMsg.From)
		e.identityStore.SetSymmetricKey(ecdhMsg.From, symmetricKey)
		logger.Debug("ECDH progress", "peer", ecdhMsg.From, "current", e.identityStore.GetSymetricKeyCount())
	})

	e.ecdhSub = sub
	if err != nil {
		return fmt.Errorf("failed to subscribe to ECDH topic: %w", err)
	}
	return nil
}

func (s *ecdhSession) Close() error {
	err := s.ecdhSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}

func (e *ecdhSession) BroadcastPublicKey() error {
	publicKeyBytes := e.publicKey.Bytes()
	msg := types.ECDHMessage{
		From:      e.nodeID,
		PublicKey: publicKeyBytes,
		Timestamp: time.Now(),
	}
	//Sign the message using existing identity store
	signature, err := e.identityStore.SignEcdhMessage(&msg)
	if err != nil {
		return fmt.Errorf("failed to sign ECDH message: %w", err)
	}
	msg.Signature = signature
	signedMsgBytes, _ := json.Marshal(msg)

	logger.Info("Starting to broadcast DH key", "nodeID", e.nodeID)
	if err := e.pubSub.Publish(ECDHExchangeTopic, signedMsgBytes); err != nil {
		return fmt.Errorf("%s failed to publish DH message because %w", e.nodeID, err)
	}
	return nil
}

func deriveConsistentInfo(a, b string) []byte {
	if a < b {
		return []byte(a + b)
	}
	return []byte(b + a)
}

// derives a symmetric key from the shared secret and peer ID using HKDF.
func (e *ecdhSession) deriveSymmetricKey(sharedSecret []byte, peerID string) []byte {
	hash := sha256.New

	// Info parameter can include context-specific data; here we use a pair of party IDs
	info := deriveConsistentInfo(e.nodeID, peerID)

	// Salt can be nil or a random value; here we use nil
	var salt []byte

	hkdf := hkdf.New(hash, sharedSecret, salt, info)

	// Derive a 32-byte symmetric key (suitable for AES-256)
	symmetricKey := make([]byte, 32)
	_, err := hkdf.Read(symmetricKey)
	if err != nil {
		e.errCh <- err
		return nil
	}
	return symmetricKey
}
