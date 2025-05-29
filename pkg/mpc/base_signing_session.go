package mpc

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/samber/lo"
)

// BaseSigningSession contains common functionality for signing sessions
type BaseSigningSession struct {
	Session
	tx                  *big.Int
	txID                string
	networkInternalCode string
}

// NewBaseSigningSession creates a new base signing session
func NewBaseSigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
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
) *BaseSigningSession {
	return &BaseSigningSession{
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
		txID:                txID,
		networkInternalCode: networkInternalCode,
	}
}

// Init handles common initialization logic for signing sessions
func (s *BaseSigningSession) Init(tx *big.Int) error {
	logger.Infof("Initializing signing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)

	keyInfo, err := s.keyinfoStore.Get(s.composeKey(s.walletID))
	if err != nil {
		return errors.Wrap(err, "Failed to get key info data")
	}

	if len(s.participantPeerIDs) < keyInfo.Threshold+1 {
		logger.Warn("Not enough participants to sign", "participants", s.participantPeerIDs, "expected", keyInfo.Threshold+1)
		return ErrNotEnoughParticipants
	}

	// check if t+1 participants are present
	result := lo.Intersect(s.participantPeerIDs, keyInfo.ParticipantPeerIDs)
	if len(result) < keyInfo.Threshold+1 {
		return fmt.Errorf(
			"Incompatible peerIDs to participate in signing. Current participants: %v, expected participants: %v",
			s.participantPeerIDs,
			keyInfo.ParticipantPeerIDs,
		)
	}

	logger.Info("Have enough participants to sign", "participants", s.participantPeerIDs)
	s.tx = tx
	return nil
}

// PublishSigningResult publishes the signing result to the result queue
func (s *BaseSigningSession) PublishSigningResult(sig *common.SignatureData, onSuccess func(data []byte)) {
	r := event.SigningResultEvent{
		ResultType:          event.SigningResultTypeSuccess,
		NetworkInternalCode: s.networkInternalCode,
		WalletID:            s.walletID,
		TxID:                s.txID,
		R:                   sig.R,
		S:                   sig.S,
		SignatureRecovery:   sig.SignatureRecovery,
	}

	bytes, err := json.Marshal(r)
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Failed to marshal raw signature")
		return
	}

	err = s.resultQueue.Enqueue(event.SigningResultCompleteTopic, bytes, &messaging.EnqueueOptions{
		IdempotententKey: s.txID,
	})
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Failed to publish sign success message")
		return
	}

	logger.Info("[SIGN] Sign successfully", "walletID", s.walletID)
	err = s.Close()
	if err != nil {
		logger.Error("Failed to close session", err)
	}

	onSuccess(bytes)
}
