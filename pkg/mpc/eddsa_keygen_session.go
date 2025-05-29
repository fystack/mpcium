package mpc

import (
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
	*BaseKeygenSession
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
	topicComposer := &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("keygen:broadcast:eddsa:%s", walletID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("keygen:direct:eddsa:%s:%s", nodeID, walletID)
		},
	}

	processSaveData := func(data any) ([]byte, error) {
		saveData, ok := data.(*keygen.LocalPartySaveData)
		if !ok {
			return nil, fmt.Errorf("invalid save data type")
		}

		publicKey := saveData.EDDSAPub
		pkX, pkY := publicKey.X(), publicKey.Y()
		pk := edwards.PublicKey{
			Curve: tss.Edwards(),
			X:     pkX,
			Y:     pkY,
		}

		return pk.SerializeCompressed(), nil
	}

	return &EDDSAKeygenSession{
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
				return fmt.Sprintf("eddsa:%s", walletID)
			},
			GetEddsaMsgRound,
			SessionTypeEddsa,
			processSaveData,
		),
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
			s.BaseKeygenSession.GenerateKey(done, saveData)
			return
		}
	}
}
