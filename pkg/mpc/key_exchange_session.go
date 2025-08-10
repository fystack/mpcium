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

type ECDHSession interface {
	StartKeyExchange() error
	BroadcastPublicKey() error
}

type ecdhSession struct {
	nodeID           string
	peerIDs          []string
	pubSub           messaging.PubSub
	ecdhSub          messaging.Subscription
	identityStore    identity.Store
	privateKey       *ecdh.PrivateKey
	publicKey        *ecdh.PublicKey
	exchangeComplete chan struct{}
	errCh            chan error
}

func NewECDHSession(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	identityStore identity.Store,
) *ecdhSession {
	return &ecdhSession{
		nodeID:           nodeID,
		peerIDs:          peerIDs,
		pubSub:           pubSub,
		identityStore:    identityStore,
		exchangeComplete: make(chan struct{}),
		errCh:            make(chan error),
	}
}

func (e *ecdhSession) StartKeyExchange() error {
	// Generate an ephemeral ECDH key pair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH key pair: %w", err)
	}

	e.privateKey = privateKey
	e.publicKey = privateKey.PublicKey()

	// Subscribe to ECDH broadcast
	sub, err := e.pubSub.Subscribe("ecdh:exchange", func(natMsg *nats.Msg) {
		var ecdhMsg types.ECDHMessage
		if err := json.Unmarshal(natMsg.Data, &ecdhMsg); err != nil {
			return
		}

		if ecdhMsg.From == e.nodeID {
			return
		}

		logger.Info("Received ECDH message from", "node", ecdhMsg.From)

		//TODO: consider how to avoid replay attack
		if err := e.identityStore.VerifySignature(&ecdhMsg); err != nil {
			e.errCh <- err
			return
		}

		peerPublicKey, err := ecdh.P256().NewPublicKey(ecdhMsg.PublicKey)
		if err != nil {
			e.errCh <- err
			return
		}
		// Perform ECDH
		sharedSecret, err := e.privateKey.ECDH(peerPublicKey)
		if err != nil {
			e.errCh <- err
			return
		}

		// Derive symmetric key using HKDF
		symmetricKey := e.deriveSymmetricKey(sharedSecret, ecdhMsg.From)
		e.identityStore.SetSymmetricKey(ecdhMsg.From, symmetricKey)

		requiredKeyCount := len(e.peerIDs)

		if e.identityStore.CheckSymmetricKeyComplete(requiredKeyCount) {
			logger.Info("Completed ECDH!", "symmetricKeyAmount", requiredKeyCount)
			logger.Info("PEER IS READY! Starting to accept MPC requests")
		}
	})
	e.ecdhSub = sub

	if err != nil {
		return fmt.Errorf("failed to subscribe to ECDH topic: %w", err)
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

	logger.Info("Starting to broadcast DH key")

	if err := e.pubSub.Publish("ecdh:exchange", signedMsgBytes); err != nil {
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
