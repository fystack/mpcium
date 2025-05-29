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
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

type EddsaSigningSession struct {
	*BaseSigningSession
	endCh chan *common.SignatureData
	data  *keygen.LocalPartySaveData
}

func NewEddsaSigningSession(
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
) *EddsaSigningSession {
	topicComposer := &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("sign:eddsa:broadcast:%s:%s", walletID, txID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("sign:eddsa:direct:%s:%s", nodeID, txID)
		},
	}

	return &EddsaSigningSession{
		BaseSigningSession: NewBaseSigningSession(
			walletID,
			txID,
			networkInternalCode,
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
		),
		endCh: make(chan *common.SignatureData),
	}
}

func (s *EddsaSigningSession) Init(tx *big.Int) error {
	if err := s.BaseSigningSession.Init(tx); err != nil {
		return err
	}

	keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
	if err != nil {
		return errors.Wrap(err, "Failed to get wallet data from KVStore")
	}

	var data keygen.LocalPartySaveData
	err = json.Unmarshal(keyData, &data)
	if err != nil {
		return errors.Wrap(err, "Failed to unmarshal wallet data")
	}

	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.Edwards(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = signing.NewLocalParty(tx, params, data, s.outCh, s.endCh)
	s.data = &data
	logger.Info("Initialized signing session successfully!")
	return nil
}

func (s *EddsaSigningSession) Sign(onSuccess func(data []byte)) {
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

			s.PublishSigningResult(sig, onSuccess)
			return
		}
	}
}
