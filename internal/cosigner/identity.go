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

func (i *localIdentity) ParticipantID() string { return i.participantID }
func (i *localIdentity) PublicKey() ed25519.PublicKey {
	return i.publicKey
}
func (i *localIdentity) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(i.privateKey, message), nil
}

type peerLookup struct{ keys map[string]ed25519.PublicKey }

func (l *peerLookup) LookupParticipant(participantID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[participantID]
	if !ok {
		return nil, fmt.Errorf("peer %s not found", participantID)
	}
	return key, nil
}

type coordinatorLookup struct{ keys map[string]ed25519.PublicKey }

func (l *coordinatorLookup) LookupCoordinator(coordinatorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[coordinatorID]
	if !ok {
		return nil, fmt.Errorf("coordinator %s not found", coordinatorID)
	}
	return key, nil
}
