package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

// Ecdsa signing session
type EcdsaSigningSession struct {
	*BaseSigningSession
	endCh chan *common.SignatureData
	data  *keygen.LocalPartySaveData
}

func NewEcdsaSigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
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
) *EcdsaSigningSession {
	topicComposer := &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("sign:ecdsa:broadcast:%s:%s", walletID, txID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("sign:ecdsa:direct:%s:%s", nodeID, txID)
		},
	}

	return &EcdsaSigningSession{
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
				return fmt.Sprintf("ecdsa:%s", walletID)
			},
			GetEcdsaMsgRound,
			SessionTypeEcdsa,
		),
		endCh: make(chan *common.SignatureData),
	}
}

func (s *EcdsaSigningSession) Init(tx *big.Int) error {
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
	params := tss.NewParameters(tss.S256(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)
	s.party = signing.NewLocalParty(tx, params, data, s.outCh, s.endCh)
	s.data = &data
	logger.Info("Initialized signing session successfully!")
	return nil
}

func (s *EcdsaSigningSession) Sign(onSuccess func(data []byte)) {
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
			publicKey := *s.data.ECDSAPub
			pk := ecdsa.PublicKey{
				Curve: publicKey.Curve(),
				X:     publicKey.X(),
				Y:     publicKey.Y(),
			}

			ok := ecdsa.Verify(&pk, s.tx.Bytes(), new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S))
			if !ok {
				s.ErrCh <- errors.New("Failed to verify signature")
				return
			}

			s.PublishSigningResult(sig, onSuccess)
			return
		}
	}
}
