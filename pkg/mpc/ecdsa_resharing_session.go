package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
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

type IResharingSession interface {
	ErrChan() <-chan error
	ListenToIncomingResharingMessageAsync()
	GetPubKeyResult() []byte
	Init()
	Resharing(done func())
}

type EcdsaResharingSession struct {
	*BaseResharingSession
	endCh chan *keygen.LocalPartySaveData
}

type ResharingSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

func NewEcdsaResharingSession(
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
	isOldParty bool,
) *EcdsaResharingSession {
	topicComposer := &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf(TopicFormatResharingBroadcast, "ecdsa", walletID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf(TopicFormatResharingDirect, "ecdsa", nodeID, walletID)
		},
	}

	base := NewBaseResharingSession(
		walletID,
		pubSub,
		direct,
		participantPeerIDs,
		selfID,
		oldPartyIDs,
		newPartyIDs,
		threshold,
		newThreshold,
		kvstore,
		keyinfoStore,
		resultQueue,
		identityStore,
		topicComposer,
		func(walletID string) string {
			return fmt.Sprintf(KeyFormatEcdsa, walletID)
		},
		GetEcdsaMsgRound,
		SessionTypeEcdsa,
		isOldParty,
	)

	// Override the reshare params with S256 curve
	base.reshareParams = tss.NewReSharingParameters(
		tss.S256(),
		tss.NewPeerContext(oldPartyIDs),
		tss.NewPeerContext(newPartyIDs),
		selfID,
		len(oldPartyIDs),
		threshold,
		len(newPartyIDs),
		newThreshold,
	)

	return &EcdsaResharingSession{
		BaseResharingSession: base,
		endCh:                make(chan *keygen.LocalPartySaveData),
	}
}

func (s *EcdsaResharingSession) Init() {
	logger.Infof("Initializing resharing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	var share keygen.LocalPartySaveData
	if s.isOldParty {
		// Get existing key data for old party
		keyData, err := s.GetExistingKeyData()
		if err != nil {
			s.ErrCh <- err
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
		share.LocalPreParams = *s.preParams
	}

	s.party = resharing.NewLocalParty(s.reshareParams, share, s.outCh, s.endCh)
	logger.Infof("[INITIALIZED] Initialized resharing session successfully partyID: %s, peerIDs %s, walletID %s, oldThreshold = %d, newThreshold = %d",
		s.selfPartyID, s.partyIDs, s.walletID, s.oldThreshold, s.newThreshold)
}

func (s *EcdsaResharingSession) Resharing(done func()) {
	logger.Info("Starting resharing", "walletID", s.walletID, "partyID", s.selfPartyID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {
		select {
		case saveData := <-s.endCh:
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

			// skip for old committee
			if saveData.ECDSAPub != nil {
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

				// Set the public key bytes
				s.pubkeyBytes = pubKeyBytes
				logger.Info("Generated public key bytes",
					"walletID", s.walletID,
					"pubKeyBytes", pubKeyBytes)
			}

			done()
			err = s.Close()
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
