// pkg/mpc/ecdh_session.go
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

type ECDHSession struct {
	nodeID  string
	peerIDs []string

	pubSub messaging.PubSub

	ecdhSub messaging.Subscription

	identityStore identity.Store
	symmetricKeys map[string][]byte // peerID -> symmetric key

	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey

	exchangeComplete chan struct{}
	errCh            chan error
}

func NewECDHSession(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	identityStore identity.Store,
) *ECDHSession {
	return &ECDHSession{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		identityStore: identityStore,
		// symmetricKeys:    make(map[string][]byte),
		exchangeComplete: make(chan struct{}),
		errCh:            make(chan error),
	}
}

func (e *ECDHSession) StartKeyExchange() error {
	// Generate an ephemeral ECDH key pair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH key pair: %w", err)
	}

	e.privateKey = privateKey
	e.publicKey = privateKey.PublicKey()

	//Subscribe to ECDH messages
	sub, err := e.pubSub.Subscribe(fmt.Sprintf("ecdh:exchange:%s", e.nodeID), func(natMsg *nats.Msg) {
		var ecdhMsg types.ECDHMessage
		if err := json.Unmarshal(natMsg.Data, &ecdhMsg); err != nil {
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

		//Check if exchange is complete
		// if len(e.identityStore.symmetricKeys) == len(e.peerIDs)-1 {
		// 	logger.Info("Finished ECDH Key Exchange")
		// 	close(e.exchangeComplete)
		// 	return
		// }
	})
	e.ecdhSub = sub

	if err != nil {
		return fmt.Errorf("failed to subscribe to ECDH topic: %w", err)
	}
	return nil
}

func (e *ECDHSession) BroadcastPublicKey() error {
	publicKeyBytes := e.publicKey.Bytes()
	for _, peerID := range e.peerIDs {
		if peerID != e.nodeID {
			msg := types.ECDHMessage{
				From:      e.nodeID,
				To:        peerID,
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

			if err := e.pubSub.Publish(fmt.Sprintf("ecdh:exchange:%s", peerID), signedMsgBytes); err != nil {
				return fmt.Errorf("failed to send public DH message to %s: %w", peerID, err)
			}
		}
	}
	return nil
}

func (e *ECDHSession) GetSymmetricKey(peerID string) ([]byte, bool) {
	key, exists := e.symmetricKeys[peerID]
	return key, exists
}

// derives a symmetric key from the shared secret and peer ID using HKDF.
func (e *ECDHSession) deriveSymmetricKey(sharedSecret []byte, peerID string) []byte {
	// Use SHA256 as the hash function for HKDF
	hash := sha256.New
	// Info parameter can include context-specific data; here we use the peerID
	var info []byte
	if e.nodeID < peerID {
		info = []byte(e.nodeID + peerID)
	} else {
		info = []byte(peerID + e.nodeID)
	}
	//TODO: Salt can be nil or a random value; here we use nil for simplicity
	var salt []byte

	// Create an HKDF instance
	hkdf := hkdf.New(hash, sharedSecret, salt, info)

	// Derive a 32-byte symmetric key (suitable for AES-256)
	symmetricKey := make([]byte, 32)
	_, err := hkdf.Read(symmetricKey)
	if err != nil {
		// In a production environment, handle this error appropriately
		panic(err) // Simplified for example; replace with proper error handling
	}
	return symmetricKey
}
