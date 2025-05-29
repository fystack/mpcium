package mpc

import (
	"crypto/ecdsa"
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
	TypeGenerateWalletSuccess = "mpc.mpc_keygen_success.%s"
)

type KeygenSession struct {
	*BaseKeygenSession
	endCh chan *keygen.LocalPartySaveData
}

type KeygenSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

func NewKeygenSession(
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
) *KeygenSession {
	topicComposer := &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("keygen:broadcast:ecdsa:%s", walletID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("keygen:direct:ecdsa:%s:%s", nodeID, walletID)
		},
	}

	processSaveData := func(data any) ([]byte, error) {
		saveData, ok := data.(*keygen.LocalPartySaveData)
		if !ok {
			return nil, fmt.Errorf("invalid save data type")
		}

		publicKey := saveData.ECDSAPub
		pubKey := &ecdsa.PublicKey{
			Curve: publicKey.Curve(),
			X:     publicKey.X(),
			Y:     publicKey.Y(),
		}

		return encoding.EncodeS256PubKey(pubKey)
	}

	return &KeygenSession{
		BaseKeygenSession: NewBaseKeygenSession(
			walletID,
			pubSub,
			direct,
			participantPeerIDs,
			selfID,
			partyIDs,
			threshold,
			kvstore,
			keyinfoStore,
			resultQueue,
			identityStore,
			topicComposer,
			func(walletID string) string {
				return fmt.Sprintf("ecdsa:%s", walletID)
			},
			GetEcdsaMsgRound,
			SessionTypeEcdsa,
			processSaveData,
		),
		endCh: make(chan *keygen.LocalPartySaveData),
	}
}

func (s *KeygenSession) Init() {
	logger.Infof("Initializing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.S256(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = keygen.NewLocalParty(params, s.outCh, s.endCh, *s.preParams)
	logger.Infof("[INITIALIZED] Initialized session successfully partyID: %s, peerIDs %s, walletID %s, threshold = %d", s.selfPartyID, s.partyIDs, s.walletID, s.threshold)
}

func (s *KeygenSession) GenerateKey(done func()) {
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
			s.BaseKeygenSession.GenerateKey(done, saveData)
			return
		}
	}
}
