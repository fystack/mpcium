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

	"github.com/nats-io/nats.go"
	"encoding/json"

)

type ECDHSession struct {
    nodeID           string
    peerIDs          []string

    pubSub           messaging.PubSub

    direct           messaging.DirectMessaging
    identityStore    identity.Store
    symmetricKeys    map[string][]byte // peerID -> symmetric key

    privateKey       *ecdh.PrivateKey
    publicKey        *ecdh.PublicKey

    exchangeComplete chan struct{}
    errCh            chan error
}

func NewECDHSession(
    nodeID string,
    peerIDs []string,
    pubSub messaging.PubSub,
    direct messaging.DirectMessaging,
    identityStore identity.Store,
) *ECDHSession {
    return &ECDHSession{
        nodeID:           nodeID,
        peerIDs:          peerIDs,
        pubSub:           pubSub,
        direct:           direct,
        identityStore:    identityStore,
        symmetricKeys:    make(map[string][]byte),
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

		logger.Info("Received ECDH message from peer node", "1st", ecdhMsg.From)

		//TODO: consider how to avoid replay attack
		 if err := e.identityStore.VerifySignature(&ecdhMsg); err != nil {
            e.errCh <- err
            return
        }

		logger.Info("Proceed onto messsage processing", "2nd", ecdhMsg.From)

        //Perform ECDH key exchange
        if err := e.processECDHMessage(&ecdhMsg); err != nil {
            e.errCh <- err
            return
        }
        //Check if exchange is complete
        if len(e.symmetricKeys) == len(e.peerIDs) {
            close(e.exchangeComplete)
            return
        }
	})
	defer sub.Unsubscribe() // Use sub to clean up
	
	if err != nil {
		return err
	}

    if err != nil {
        return fmt.Errorf("failed to subscribe to ECDH topic: %w", err)
    }
    
    // Broadcast public DH key to all other peers
    return e.broadcastPublicKey()
}

func (e *ECDHSession) broadcastPublicKey() error {
    publicKeyBytes := e.publicKey.Bytes()
    
    for _, peerID := range e.peerIDs {
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
        
        if err := e.direct.Send(fmt.Sprintf("ecdh:exchange:%s", peerID), signedMsgBytes); err != nil {
            return fmt.Errorf("failed to send public DH message to %s: %w", peerID, err)
        }
    }
    return nil
}

func (e *ECDHSession) processECDHMessage(msg *types.ECDHMessage) error {
    peerPublicKey, err := ecdh.P256().NewPublicKey(msg.PublicKey)
    if err != nil {
        return fmt.Errorf("invalid peer public key: %w", err)
    }
    
    // Perform ECDH
    sharedSecret, err := e.privateKey.ECDH(peerPublicKey)
    if err != nil {
        return fmt.Errorf("ECDH failed: %w", err)
    }
    
    // Derive symmetric key using HKDF
    symmetricKey := e.deriveSymmetricKey(sharedSecret, msg.From)
    e.symmetricKeys[msg.From] = symmetricKey
    
    return nil
}

func (e *ECDHSession) GetSymmetricKey(peerID string) ([]byte, bool) {
    key, exists := e.symmetricKeys[peerID]
    return key, exists
}

// deriveSymmetricKey derives a symmetric key from the shared secret and peer ID using HKDF.
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

func (e *ECDHSession) WaitForCompletion() error {
    select {
    case <-e.exchangeComplete:
        return nil
    case err := <-e.errCh:
        return err
    case <-time.After(30 * time.Second):
        return fmt.Errorf("ECDH key exchange timeout")
    }
}