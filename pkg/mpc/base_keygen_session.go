package mpc

import (
	"encoding/json"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

// BaseKeygenSession contains common functionality for keygen sessions
type BaseKeygenSession struct {
	Session
	processSaveData func(interface{}) ([]byte, error)
}

// NewBaseKeygenSession creates a new base keygen session
func NewBaseKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	participantPeerIDs []string,
	selfID *tss.PartyID,
	partyIDs []*tss.PartyID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	topicComposer *TopicComposer,
	composeKey KeyComposerFn,
	getRoundFunc GetRoundFunc,
	sessionType SessionType,
	processSaveData func(interface{}) ([]byte, error),
) *BaseKeygenSession {
	return &BaseKeygenSession{
		Session: Session{
			walletID:           walletID,
			pubSub:             pubSub,
			direct:             direct,
			threshold:          threshold,
			participantPeerIDs: participantPeerIDs,
			selfPartyID:        selfID,
			partyIDs:           partyIDs,
			outCh:              make(chan tss.Message),
			ErrCh:              make(chan error),
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			topicComposer:      topicComposer,
			composeKey:         composeKey,
			getRoundFunc:       getRoundFunc,
			resultQueue:        resultQueue,
			sessionType:        sessionType,
			identityStore:      identityStore,
		},
		processSaveData: processSaveData,
	}
}

// GenerateKey handles the common key generation flow
func (s *BaseKeygenSession) GenerateKey(done func(), saveData interface{}) {
	keyBytes, err := json.Marshal(saveData)
	if err != nil {
		s.ErrCh <- err
		return
	}

	err = s.kvstore.Put(s.composeKey(s.walletID), keyBytes)
	if err != nil {
		logger.Error("Failed to save key", err, "walletID", s.walletID)
		s.ErrCh <- err
		return
	}

	keyInfo := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.participantPeerIDs,
		Threshold:          s.threshold,
		IsReshared:         false,
	}

	err = s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo)
	if err != nil {
		logger.Error("Failed to save keyinfo", err, "walletID", s.walletID)
		s.ErrCh <- err
		return
	}

	pubKeyBytes, err := s.processSaveData(saveData)
	if err != nil {
		logger.Error("failed to process save data", err)
		s.ErrCh <- err
		return
	}

	s.pubkeyBytes = pubKeyBytes
	done()
	err = s.Close()
	if err != nil {
		logger.Error("Failed to close session", err)
	}
}
