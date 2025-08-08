package mpc

import (
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

type eddsaReshareSession struct {
	*session
	isNewParty    bool
	newPeerIDs    []string
	reshareParams *tss.ReSharingParameters
	endCh         chan *keygen.LocalPartySaveData
}

func NewEDDSAReshareSession(
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
	newPeerIDs []string,
	isNewParty bool,
	version int,
) *eddsaReshareSession {
	session := session{
		walletID:           walletID,
		pubSub:             pubSub,
		direct:             direct,
		threshold:          threshold,
		version:            version,
		participantPeerIDs: participantPeerIDs,
		selfPartyID:        selfID,
		partyIDs:           newPartyIDs,
		outCh:              make(chan tss.Message),
		ErrCh:              make(chan error),
		kvstore:            kvstore,
		keyinfoStore:       keyinfoStore,
		topicComposer: &TopicComposer{
			ComposeBroadcastTopic: func() string {
				return fmt.Sprintf("reshare:broadcast:eddsa:%s", walletID)
			},
			ComposeDirectTopic: func(fromRouteID string, toRouteID string) string {
				return fmt.Sprintf("reshare:direct:eddsa:%s:%s:%s", fromRouteID, toRouteID, walletID)
			},
		},
		composeKey: func(walletID string) string {
			return fmt.Sprintf("eddsa:%s", walletID)
		},
		getRoundFunc:  GetEddsaMsgRound,
		resultQueue:   resultQueue,
		sessionType:   SessionTypeEDDSA,
		identityStore: identityStore,
	}

	reshareParams := tss.NewReSharingParameters(
		tss.Edwards(),
		tss.NewPeerContext(oldPartyIDs),
		tss.NewPeerContext(newPartyIDs),
		selfID,
		len(oldPartyIDs),
		threshold,
		len(newPartyIDs),
		newThreshold,
	)

	return &eddsaReshareSession{
		session:       &session,
		reshareParams: reshareParams,
		isNewParty:    isNewParty,
		newPeerIDs:    newPeerIDs,
		endCh:         make(chan *keygen.LocalPartySaveData),
	}
}

func (s *eddsaReshareSession) Init() {
	logger.Infof("Initializing resharing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	var share keygen.LocalPartySaveData
	if s.isNewParty {
		// Initialize empty share data for new party
		share = keygen.NewLocalPartySaveData(len(s.partyIDs))
	} else {
		err := s.loadOldShareDataGeneric(s.walletID, s.GetVersion(), &share)
		if err != nil {
			s.ErrCh <- err
			return
		}
	}
	s.party = resharing.NewLocalParty(s.reshareParams, share, s.outCh, s.endCh)
	logger.Infof("[INITIALIZED] Initialized resharing session successfully partyID: %s, peerIDs %s, walletID %s, oldThreshold = %d, newThreshold = %d",
		s.selfPartyID, s.partyIDs, s.walletID, s.threshold, s.reshareParams.NewThreshold())
}

func (s *eddsaReshareSession) Reshare(done func()) {
	logger.Info("Starting resharing", "walletID", s.walletID, "partyID", s.selfPartyID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {
		select {
		case saveData := <-s.endCh:
			if saveData.EDDSAPub != nil {
				keyBytes, err := json.Marshal(saveData)
				if err != nil {
					s.ErrCh <- err
					return
				}

				newVersion := s.GetVersion() + 1
				key := s.composeKey(walletIDWithVersion(s.walletID, newVersion))
				if err := s.kvstore.Put(key, keyBytes); err != nil {
					s.ErrCh <- err
					return
				}

				keyInfo := keyinfo.KeyInfo{
					ParticipantPeerIDs: s.newPeerIDs,
					Threshold:          s.reshareParams.NewThreshold(),
					Version:            newVersion,
				}

				// Save key info with resharing flag
				if err := s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo); err != nil {
					s.ErrCh <- err
					return
				}

				// skip for old committee
				if saveData.EDDSAPub != nil {

					// Get public key
					publicKey := saveData.EDDSAPub
					pkX, pkY := publicKey.X(), publicKey.Y()
					pk := edwards.PublicKey{
						Curve: tss.Edwards(),
						X:     pkX,
						Y:     pkY,
					}

					pubKeyBytes := pk.SerializeCompressed()
					s.pubkeyBytes = pubKeyBytes

					logger.Info("Generated public key bytes",
						"walletID", s.walletID,
						"pubKeyBytes", pubKeyBytes)
				}
			}
			done()
			err := s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			return
		case msg := <-s.outCh:
			// Handle the message
			s.handleTssMessage(msg)
		}
	}
}
