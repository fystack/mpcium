package mpc

import (
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

type EDDSAKeygenSession struct {
	Session
	endCh chan *keygen.LocalPartySaveData
}

type EDDSAKeygenSuccessEvent struct {
	WalletID string `json:"wallet_id"`
	PubKey   []byte `json:"pub_key"`
}

func NewEDDSAKeygenSession(
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
) *EDDSAKeygenSession {
	return &EDDSAKeygenSession{Session: Session{
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
		topicComposer: &TopicComposer{
			ComposeBroadcastTopic: func() string {
				return fmt.Sprintf("keygen:broadcast:eddsa:%s", walletID)
			},
			ComposeDirectTopic: func(nodeID string) string {
				return fmt.Sprintf("keygen:direct:eddsa:%s:%s", nodeID, walletID)
			},
		},
		composeKey: func(waleltID string) string {
			return fmt.Sprintf("eddsa:%s", waleltID)
		},
		getRoundFunc:  GetEddsaMsgRound,
		resultQueue:   resultQueue,
		sessionType:   SessionTypeEddsa,
		identityStore: identityStore,
	},
		endCh: make(chan *keygen.LocalPartySaveData),
	}
}

func (s *EDDSAKeygenSession) Init() {
	logger.Infof("Initializing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.Edwards(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = keygen.NewLocalParty(params, s.outCh, s.endCh)
	logger.Infof("[INITIALIZED] Initialized session successfully partyID: %s, peerIDs %s, walletID %s, threshold = %d", s.selfPartyID, s.partyIDs, s.walletID, s.threshold)
}

func (s *EDDSAKeygenSession) GenerateKey(done func()) {
	logger.Info("Starting to generate key", "walletID", s.walletID)
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

			publicKey := saveData.EDDSAPub
			pkX, pkY := publicKey.X(), publicKey.Y()
			pk := edwards.PublicKey{
				Curve: tss.Edwards(),
				X:     pkX,
				Y:     pkY,
			}

			pubKeyBytes := pk.SerializeCompressed()
			s.pubkeyBytes = pubKeyBytes

			err = s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			done()
			return
		}
	}
}
