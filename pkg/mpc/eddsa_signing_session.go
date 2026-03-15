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
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/security"
	"github.com/samber/lo"
)

type eddsaSigningSession struct {
	session
	endCh               chan *common.SignatureData
	data                *keygen.LocalPartySaveData
	tx                  *big.Int
	txID                string
	clientID            string
	networkInternalCode string
	derivationPath      []uint32
	ckd                 *CKD
}

func newEDDSASigningSession(
	walletID string,
	txID string,
	clientID string,
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
	derivationPath []uint32,
	idempotentKey string,
	ckd *CKD,
) *eddsaSigningSession {
	return &eddsaSigningSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			direct:             direct,
			threshold:          threshold,
			participantPeerIDs: participantPeerIDs,
			selfPartyID:        selfID,
			partyIDs:           partyIDs,
			outCh:              make(chan tss.Message),
			ErrCh:              make(chan error, 1),
			doneCh:             make(chan struct{}),
			kvstore:      kvstore,
			keyinfoStore: keyinfoStore,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:eddsa:broadcast:%s:%s", walletID, txID)
				},
				ComposeDirectTopic: func(fromID string, toID string) string {
					return fmt.Sprintf("sign:eddsa:direct:%s:%s:%s", fromID, toID, txID)
				},
			},
			composeKey: func(waleltID string) string {
				return fmt.Sprintf("eddsa:%s", waleltID)
			},
			getRoundFunc:  GetEddsaMsgRound,
			resultQueue:   resultQueue,
			identityStore: identityStore,
			idempotentKey: idempotentKey,
		},
		endCh:               make(chan *common.SignatureData),
		txID:                txID,
		clientID:            clientID,
		networkInternalCode: networkInternalCode,
		derivationPath:      derivationPath,
		ckd:                 ckd,
	}
}

func (s *eddsaSigningSession) Init(tx *big.Int) error {
	logger.Infof("Initializing signing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	ctx := tss.NewPeerContext(s.partyIDs)
	params := tss.NewParameters(tss.Edwards(), ctx, s.selfPartyID, len(s.partyIDs), s.threshold)

	keyInfo, err := s.keyinfoStore.Get(s.composeKey(s.walletID))
	if err != nil {
		return errors.Wrap(err, "Failed to get key info data")
	}

	if len(s.participantPeerIDs) < keyInfo.Threshold+1 {
		logger.Warn("Not enough participants to sign, expected %d, got %d", keyInfo.Threshold+1, len(s.participantPeerIDs))
		return ErrNotEnoughParticipants
	}

	// check if t+1 participants are present
	result := lo.Intersect(s.participantPeerIDs, keyInfo.ParticipantPeerIDs)
	if len(result) < keyInfo.Threshold+1 {
		return fmt.Errorf(
			"Incompatible peerIDs to participate in signing. Current participants: %v, expected participants: %v",
			s.participantPeerIDs,
			keyInfo.ParticipantPeerIDs,
		)
	}

	logger.Info("Have enough participants to sign", "participants", s.participantPeerIDs)
	key := s.composeKey(walletIDWithVersion(s.walletID, keyInfo.Version))
	keyData, err := s.kvstore.Get(key)
	if err != nil {
		return errors.Wrap(err, "Failed to get wallet data from KVStore")
	}
	// Check if all the participants of the key are present
	var data keygen.LocalPartySaveData
	err = json.Unmarshal(keyData, &data)
	security.ZeroBytes(keyData)
	if err != nil {
		return errors.Wrap(err, "Failed to unmarshal wallet data")
	}
	

	if len(s.derivationPath) > 0 {
		il, extendedChildPk, errorDerivation := s.ckd.Derive(s.walletID, data.EDDSAPub, s.derivationPath, tss.Edwards())
		if errorDerivation != nil {
			return errors.Wrap(errorDerivation, fmt.Sprintf("Failed to derive key, derivationPath: %v", s.derivationPath))
		}
		keyDerivationDelta := il
		err = s.ckd.EDDSAUpdateSinglePublicKeyAndAdjustBigXj(keyDerivationDelta, &data, extendedChildPk.PublicKey, tss.Edwards())
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to update public key, derivationPath: %v", s.derivationPath))
		}

		s.party = signing.NewLocalPartyWithKDD(tx, params, data, keyDerivationDelta, s.outCh, s.endCh, 0)

	} else {
		s.party = signing.NewLocalParty(tx, params, data, s.outCh, s.endCh)
	}
	s.data = &data
	s.version = keyInfo.Version
	s.tx = tx
	logger.Info("Initialized sigining session successfully!")
	return nil
}

func (s *eddsaSigningSession) Sign(onSuccess func(data []byte)) {
	logger.Info("Starting signing", "walletID", s.walletID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.sendErr(err)
		}
	}()

	for {
		select {
		case <-s.doneCh:
			logger.Info("EDDSA signing session stopped", "walletID", s.walletID)
			return
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
				s.sendErr(errors.New("Failed to verify signature"))
				return
			}

			r := event.SigningResultEvent{
				ResultType:          event.ResultTypeSuccess,
				NetworkInternalCode: s.networkInternalCode,
				WalletID:            s.walletID,
				TxID:                s.txID,
				Signature:           sig.Signature,
			}

			bytes, err := json.Marshal(r)
			if err != nil {
				s.sendErr(errors.Wrap(err, "Failed to marshal raw signature"))
				return
			}

			resultTopic := fmt.Sprintf(TypeSigningResultFmt, s.clientID, s.txID)
			err = s.resultQueue.Enqueue(resultTopic, bytes, &messaging.EnqueueOptions{
				IdempotententKey: s.idempotentKey,
			})
			if err != nil {
				s.sendErr(errors.Wrap(err, "Failed to publish sign success message"))
				return
			}

			logger.Info("[SIGN] Sign successfully", "walletID", s.walletID)

			err = s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}

			onSuccess(bytes)
			return
		}
	}
}
// Close cleans up the EDDSA signing session by zeroing all sensitive data.
func (s *eddsaSigningSession) Close() error {
	if s == nil {
		return nil
	}

	// Zero out sensitive data
	if s.data != nil {
		security.ZeroEddsaKeygenLocalPartySaveData(s.data)
		s.data = nil
	}

	// Clear other sensitive fields
	if s.tx != nil {
		s.tx.SetInt64(0)
		s.tx = nil
	}

	// Clear the derivation path
	if s.derivationPath != nil {
		for i := range s.derivationPath {
			s.derivationPath[i] = 0
		}
		s.derivationPath = nil
	}

	// Clear CKD reference
	s.ckd = nil

	// Avoid closing endCh here to prevent send-on-closed-channel panics.
	// Let the producer side (tss-lib) own channel lifetime.
	s.endCh = nil

	// Call parent's Close() to handle cleanup of subscriptions
	return s.session.Close()
}
