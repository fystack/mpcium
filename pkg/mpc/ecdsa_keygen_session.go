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

type KeyGenSession interface {
	Session

	Init()
	GenerateKey(done func())
	GetPubKeyResult() []byte
}

type ecdsaKeygenSession struct {
	session
	endCh chan *keygen.LocalPartySaveData
}

func newECDSAKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	participantPeerIDs []string,
	selfID *tss.PartyID,
	partyIDs []*tss.PartyID,
	threshold int,
	preParams *keygen.LocalPreParams,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *ecdsaKeygenSession {
	return &ecdsaKeygenSession{
		session: session{
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
			preParams:          preParams,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:ecdsa:%s", walletID)
				},
				ComposeDirectTopic: func(fromID string, toID string) string {
					return fmt.Sprintf("keygen:direct:ecdsa:%s:%s:%s", fromID, toID, walletID)
				},
			},
			composeKey: func(walletID string) string {
				return fmt.Sprintf("ecdsa:%s", walletID)
			},
			getRoundFunc:  GetEcdsaMsgRound,
			resultQueue:   resultQueue,
			sessionType:   SessionTypeECDSA,
			identityStore: identityStore,
		},
		endCh: make(chan *keygen.LocalPartySaveData),
	}
}

func (s *ecdsaKeygenSession) Init() {
	logger.Infof("Initializing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.S256(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = keygen.NewLocalParty(params, s.outCh, s.endCh, *s.preParams)
	logger.Infof("[INITIALIZED] Initialized session successfully partyID: %s, peerIDs %s, walletID %s, threshold = %d", s.selfPartyID, s.partyIDs, s.walletID, s.threshold)
}

func (s *ecdsaKeygenSession) GenerateKey(done func()) {
	logger.Info("Starting to generate key ECDSA", "walletID", s.walletID)
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
			err = s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			done()
			return
		}
	}
}
