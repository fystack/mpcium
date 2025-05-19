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

type EDDSAResharingSession struct {
	Session
	isOldParty   bool
	oldPartyIDs  []*tss.PartyID
	oldThreshold int
	newThreshold int
	endCh        chan *keygen.LocalPartySaveData
}

func EDDSANewResharingSession(
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
	isOldParty bool,
) *EDDSAResharingSession {
	oldCtx := tss.NewPeerContext(oldPartyIDs)
	newCtx := tss.NewPeerContext(newPartyIDs)
	reshareParams := tss.NewReSharingParameters(
		tss.Edwards(),
		oldCtx,
		newCtx,
		selfID,
		len(oldPartyIDs),
		threshold,
		len(newPartyIDs),
		newThreshold,
	)
	return &EDDSAResharingSession{
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
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf(TopicFormatResharingBroadcast, "eddsa", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf(TopicFormatResharingDirect, "eddsa", nodeID, walletID)
				},
			},
			composeKey: func(walletID string) string {
				return fmt.Sprintf(KeyFormatEddsa, walletID)
			},
			getRoundFunc:  GetEddsaMsgRound,
			resultQueue:   resultQueue,
			sessionType:   SessionTypeEddsa,
			identityStore: identityStore,
		},
		isOldParty:   isOldParty,
		oldPartyIDs:  oldPartyIDs,
		oldThreshold: threshold,
		newThreshold: newThreshold,
		endCh:        make(chan *keygen.LocalPartySaveData),
	}
}

func (s *EDDSAResharingSession) Init() {
	logger.Infof("Initializing EDDSA resharing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	var share keygen.LocalPartySaveData
	if s.isOldParty {
		// Get existing key data for old party
		keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
		if err != nil {
			fmt.Println("err", err)
			s.ErrCh <- fmt.Errorf("failed to get wallet data from KVStore: %w", err)
			return
		}
		err = json.Unmarshal(keyData, &share)
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to unmarshal wallet data: %w", err)
			return
		}
	} else {
		// Initialize empty share data for new party
		share = keygen.NewLocalPartySaveData(len(s.partyIDs))
	}
	s.party = resharing.NewLocalParty(s.reshareParams, share, s.outCh, s.endCh)
	logger.Infof("[INITIALIZED] Initialized EDDSA resharing session successfully partyID: %s, peerIDs %s, walletID %s, oldThreshold = %d, newThreshold = %d",
		s.selfPartyID, s.partyIDs, s.walletID, s.oldThreshold, s.newThreshold)
}

func (s *EDDSAResharingSession) Resharing(done func()) {
	logger.Info("Starting EDDSA resharing", "walletID", s.walletID, "partyID", s.selfPartyID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {
		select {
		case saveData := <-s.endCh:
			// skip for old committee
			if saveData.EDDSAPub != nil {
				keyBytes, err := json.Marshal(saveData)
				if err != nil {
					s.ErrCh <- err
					return
				}

				if err := s.SaveKeyData(keyBytes); err != nil {
					s.ErrCh <- err
					return
				}

				// Save key info with resharing flag
				if err := s.SaveKeyInfo(true); err != nil {
					s.ErrCh <- err
					return
				}

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

			done()
			err := s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			return
		case msg := <-s.outCh:
			// Handle the message
			s.handleResharingMessage(msg)
		}
	}
}
