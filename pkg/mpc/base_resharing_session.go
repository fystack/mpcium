package mpc

import (
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
)

// BaseResharingSession contains common functionality for resharing sessions
type BaseResharingSession struct {
	Session
	isOldParty   bool
	oldPartyIDs  []*tss.PartyID
	oldThreshold int
	newThreshold int
}

// NewBaseResharingSession creates a new base resharing session
func NewBaseResharingSession(
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	participantPeerIDs []string,
	selfID *tss.PartyID,
	oldPartyIDs []*tss.PartyID,
	newPartyIDs []*tss.PartyID,
	threshold int,
	newThreshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	topicComposer *TopicComposer,
	composeKey KeyComposerFn,
	getRoundFunc GetRoundFunc,
	sessionType SessionType,
	isOldParty bool,
) *BaseResharingSession {
	oldCtx := tss.NewPeerContext(oldPartyIDs)
	newCtx := tss.NewPeerContext(newPartyIDs)
	reshareParams := tss.NewReSharingParameters(
		tss.S256(), // This will be overridden by the specific session
		oldCtx,
		newCtx,
		selfID,
		len(oldPartyIDs),
		threshold,
		len(newPartyIDs),
		newThreshold,
	)

	return &BaseResharingSession{
		Session: Session{
			walletID:           walletID,
			pubSub:             pubSub,
			direct:             direct,
			threshold:          newThreshold,
			participantPeerIDs: participantPeerIDs,
			selfPartyID:        selfID,
			partyIDs:           newPartyIDs,
			outCh:              make(chan tss.Message),
			ErrCh:              make(chan error),
			reshareParams:      reshareParams,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			topicComposer:      topicComposer,
			composeKey:         composeKey,
			getRoundFunc:       getRoundFunc,
			resultQueue:        resultQueue,
			sessionType:        sessionType,
			identityStore:      identityStore,
		},
		isOldParty:   isOldParty,
		oldPartyIDs:  oldPartyIDs,
		oldThreshold: threshold,
		newThreshold: newThreshold,
	}
}

// SaveKeyData saves the key data to the KV store
func (s *BaseResharingSession) SaveKeyData(keyBytes []byte) error {
	err := s.kvstore.Put(s.composeKey(s.walletID), keyBytes)
	if err != nil {
		return fmt.Errorf("failed to save key data: %w", err)
	}
	return nil
}

// SaveKeyInfo saves the key info with resharing flag
func (s *BaseResharingSession) SaveKeyInfo(isReshared bool) error {
	keyInfo := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.participantPeerIDs,
		Threshold:          s.newThreshold,
		IsReshared:         isReshared,
	}

	err := s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo)
	if err != nil {
		return fmt.Errorf("failed to save key info: %w", err)
	}
	return nil
}

// GetExistingKeyData retrieves existing key data for old party
func (s *BaseResharingSession) GetExistingKeyData() ([]byte, error) {
	keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet data from KVStore: %w", err)
	}
	return keyData, nil
}
