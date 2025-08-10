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

type eddsaKeygenSession struct {
	session
	endCh chan *keygen.LocalPartySaveData
}

func newEDDSAKeygenSession(
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
) *eddsaKeygenSession {
	return &eddsaKeygenSession{session: session{
		walletID:           walletID,
		pubSub:             pubSub,
		direct:             direct,
		threshold:          threshold,
		version:            DefaultVersion,
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
			ComposeDirectTopic: func(fromID string, toID string) string {
				return fmt.Sprintf("keygen:direct:eddsa:%s:%s:%s", fromID, toID, walletID)
			},
		},
		composeKey: func(waleltID string) string {
			return fmt.Sprintf("eddsa:%s", waleltID)
		},
		getRoundFunc:  GetEddsaMsgRound,
		resultQueue:   resultQueue,
		sessionType:   SessionTypeEDDSA,
		identityStore: identityStore,
	},
		endCh: make(chan *keygen.LocalPartySaveData),
	}
}

func (s *eddsaKeygenSession) Init() {
	logger.Infof("Initializing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.Edwards(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = keygen.NewLocalParty(params, s.outCh, s.endCh)
	logger.Infof("[INITIALIZED] Initialized session successfully partyID: %s, peerIDs %s, walletID %s, threshold = %d", s.selfPartyID, s.partyIDs, s.walletID, s.threshold)
}

func (s *eddsaKeygenSession) GenerateKey(done func()) {
	logger.Info("Starting to generate key EDDSA", "walletID", s.walletID)
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

			err = s.kvstore.Put(s.composeKey(walletIDWithVersion(s.walletID, s.GetVersion())), keyBytes)
			if err != nil {
				logger.Error("Failed to save key", err, "walletID", s.walletID)
				s.ErrCh <- err
				return
			}

			keyInfo := keyinfo.KeyInfo{
				ParticipantPeerIDs: s.participantPeerIDs,
				Threshold:          s.threshold,
				Version:            s.GetVersion(),
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
