package cosigner

import (
	"crypto/ed25519"
	"fmt"
)

type localIdentity struct {
	participantID string
	publicKey     ed25519.PublicKey
	privateKey    ed25519.PrivateKey
}

func NewLocalIdentity(nodeID string, privateKey []byte) (*localIdentity, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("node_id is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity private key size")
	}
	private := ed25519.PrivateKey(append([]byte(nil), privateKey...))
	public := private.Public().(ed25519.PublicKey)
	return &localIdentity{participantID: nodeID, publicKey: public, privateKey: private}, nil
}

func (i *localIdentity) ParticipantID() string { return i.participantID }
func (i *localIdentity) PublicKey() ed25519.PublicKey {
	return i.publicKey
}
func (i *localIdentity) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(i.privateKey, message), nil
}

type peerLookup struct{ keys map[string]ed25519.PublicKey }

func NewPeerLookup(keys map[string]ed25519.PublicKey) *peerLookup {
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		cloned[id] = append([]byte(nil), key...)
	}
	return &peerLookup{keys: cloned}
}

func (l *peerLookup) LookupParticipant(participantID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[participantID]
	if !ok {
		return nil, fmt.Errorf("peer %s not found", participantID)
	}
	return key, nil
}

type coordinatorLookup struct{ keys map[string]ed25519.PublicKey }

func NewCoordinatorLookup(coordinatorID string, publicKey []byte) (*coordinatorLookup, error) {
	if coordinatorID == "" {
		return nil, fmt.Errorf("coordinator_id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid coordinator public key size")
	}
	return &coordinatorLookup{keys: map[string]ed25519.PublicKey{
		coordinatorID: append([]byte(nil), publicKey...),
	}}, nil
}

func (l *coordinatorLookup) LookupCoordinator(coordinatorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[coordinatorID]
	if !ok {
		return nil, fmt.Errorf("coordinator %s not found", coordinatorID)
	}
	return key, nil
}
