package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

const (
	TypeResharingSuccess = "mpc.mpc_resharing_success.%s"
)

type ResharingSession struct {
	Session
	oldThreshold int
	newThreshold int
	endCh        chan *keygen.LocalPartySaveData
	party        tss.Party
}

type ResharingSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

func NewResharingSession(
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	participantPeerIDs []string,
	selfID *tss.PartyID,
	oldPartyIDs []*tss.PartyID,
	newPartyIDs []*tss.PartyID,
	threshold int,
	newThreshold int,
	preParams *keygen.LocalPreParams,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,

) *ResharingSession {
	return &ResharingSession{
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
			preParams:          preParams,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("resharing:broadcast:ecdsa:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("resharing:direct:ecdsa:%s:%s", nodeID, walletID)
				},
			},
			composeKey: func(walletID string) string {
				return fmt.Sprintf("ecdsa:%s", walletID)
			},
			getRoundFunc:  GetEcdsaMsgRound,
			resultQueue:   resultQueue,
			sessionType:   SessionTypeEcdsa,
			identityStore: identityStore,
		},
		oldThreshold: threshold,
		newThreshold: newThreshold,
		endCh:        make(chan *keygen.LocalPartySaveData),
	}
}

func (s *ResharingSession) Init() {
	logger.Infof("Initializing resharing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.S256(), ctx, s.selfPartyID, len(s.partyIDs), s.newThreshold)

	// Get existing key data
	keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to get wallet data from KVStore: %w", err)
		return
	}

	var data keygen.LocalPartySaveData
	err = json.Unmarshal(keyData, &data)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to unmarshal wallet data: %w", err)
		return
	}

	// Create resharing party
	s.party = keygen.NewLocalParty(params, s.outCh, s.endCh, *s.preParams)
	logger.Infof("[INITIALIZED] Initialized resharing session successfully partyID: %s, peerIDs %s, walletID %s, oldThreshold = %d, newThreshold = %d",
		s.selfPartyID, s.partyIDs, s.walletID, s.oldThreshold, s.newThreshold)
}

func (s *ResharingSession) Resharing(done func()) {
	logger.Info("Starting resharing", "walletID", s.walletID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {
		select {
		case msg := <-s.outCh:
			s.handleTssMessage(msg)
		case saveData := <-s.endCh:
			keyBytes, err := json.Marshal(saveData)
			if err != nil {
				s.ErrCh <- err
				return
			}

			// Save new key data
			err = s.kvstore.Put(s.composeKey(s.walletID), keyBytes)
			if err != nil {
				logger.Error("Failed to save key", err, "walletID", s.walletID)
				s.ErrCh <- err
				return
			}

			// Update key info with new threshold and participants
			keyInfo := keyinfo.KeyInfo{
				ParticipantPeerIDs: s.participantPeerIDs,
				Threshold:          s.newThreshold,
			}

			err = s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo)
			if err != nil {
				logger.Error("Failed to save keyinfo", err, "walletID", s.walletID)
				s.ErrCh <- err
				return
			}

			// Get public key
			publicKey := saveData.ECDSAPub
			pubKey := &ecdsa.PublicKey{
				Curve: publicKey.Curve(),
				X:     publicKey.X(),
				Y:     publicKey.Y(),
			}

			pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
			if err != nil {
				logger.Error("failed to encode public key", err)
				s.ErrCh <- fmt.Errorf("failed to encode public key: %w", err)
				return
			}
			s.pubkeyBytes = pubKeyBytes

			// Close session and call done callback
			err = s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			done()
			return
		}
	}
}
