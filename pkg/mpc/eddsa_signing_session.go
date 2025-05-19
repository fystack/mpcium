package mpc

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/samber/lo"
)

type EDDSASigningSession struct {
	Session
	endCh               chan *common.SignatureData
	data                *keygen.LocalPartySaveData
	tx                  *big.Int
	txID                string
	networkInternalCode string
}

func NewEDDSASigningSession(
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
) *EDDSASigningSession {
	return &EDDSASigningSession{
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
			// preParams:          preParams,
			kvstore:      kvstore,
			keyinfoStore: keyinfoStore,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:eddsa:broadcast:%s:%s", walletID, txID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:eddsa:direct:%s:%s", nodeID, txID)
				},
			},
			composeKey: func(waleltID string) string {
				return fmt.Sprintf("eddsa:%s", waleltID)
			},
			getRoundFunc:  GetEddsaMsgRound,
			resultQueue:   resultQueue,
			identityStore: identityStore,
		},
		endCh:               make(chan *common.SignatureData),
		txID:                txID,
		networkInternalCode: networkInternalCode,
	}
}

func (s *EDDSASigningSession) Init(tx *big.Int) error {
	logger.Infof("Initializing signing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.Edwards(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)

	keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
	if err != nil {
		return errors.Wrap(err, "Failed to get wallet data from KVStore")
	}

	keyInfo, err := s.keyinfoStore.Get(s.composeKey(s.walletID))
	if err != nil {
		return errors.Wrap(err, "Failed to get key info data")
	}

	if len(s.participantPeerIDs) < keyInfo.Threshold+1 {
		logger.Warn("Not enough participants to sign, expected %d, got %d", keyInfo.Threshold+1, len(s.participantPeerIDs))
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
	// Check if all the participants of the key are present
	var data keygen.LocalPartySaveData
	err = json.Unmarshal(keyData, &data)
	if err != nil {
		return errors.Wrap(err, "Failed to unmarshal wallet data")
	}
	s.party = signing.NewLocalParty(tx, params, data, s.outCh, s.endCh)
	s.data = &data
	s.tx = tx
	logger.Info("Initialized sigining session successfully!")
	return nil
}

func (s *EDDSASigningSession) Sign(onSuccess func(data []byte)) {
	logger.Info("Starting signing", "walletID", s.walletID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {

		select {
		case msg := <-s.outCh:
			s.handleTssMessage(msg)
		case sig := <-s.endCh:
			publicKey := *s.data.EDDSAPub
			pk := edwards.PublicKey{
				Curve: tss.Edwards(),
				X:     publicKey.X(),
				Y:     publicKey.Y(),
			}

			ok := edwards.Verify(&pk, s.tx.Bytes(), new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S))
			if !ok {
				s.ErrCh <- errors.New("Failed to verify signature")
				return
			}

			r := event.SigningResultEvent{
				ResultType:          event.SigningResultTypeSuccess,
				NetworkInternalCode: s.networkInternalCode,
				WalletID:            s.walletID,
				TxID:                s.txID,
				Signature:           sig.Signature,
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
			return
		}

	}
}
