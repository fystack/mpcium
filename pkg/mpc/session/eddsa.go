package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/party"
)

type EDDSASession struct {
	*session
}

func NewEDDSASession(walletID string, partyID *tss.PartyID, partyIDs []*tss.PartyID, threshold int, pubSub messaging.PubSub, direct messaging.DirectMessaging, identityStore identity.Store, kvstore kvstore.KVStore, keyinfoStore keyinfo.Store) *EDDSASession {
	s := NewSession(PurposeKeygen, walletID, pubSub, direct, identityStore, kvstore, keyinfoStore)
	s.party = party.NewEDDSAParty(walletID, partyID, partyIDs, threshold, nil, nil, s.errCh)
	s.topicComposer = &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("broadcast:eddsa:%s", walletID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("direct:eddsa:%s:%s", nodeID, walletID)
		},
	}
	s.composeKey = func(walletID string) string {
		return fmt.Sprintf("eddsa:%s", walletID)
	}
	return &EDDSASession{
		session: s,
	}
}

func (s *EDDSASession) StartKeygen(ctx context.Context, send func(tss.Message), finish func([]byte)) {
	s.party.StartKeygen(ctx, send, finish)
}

func (s *EDDSASession) StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), finish func([]byte)) {
	s.party.StartSigning(ctx, msg, send, finish)
}

func (s *EDDSASession) StartResharing(ctx context.Context, oldPartyIDs []*tss.PartyID, newPartyIDs []*tss.PartyID, oldThreshold int, newThreshold int, send func(tss.Message), finish func([]byte)) {
	s.party.StartResharing(ctx, oldPartyIDs, newPartyIDs, oldThreshold, newThreshold, send, finish)
}

func (s *EDDSASession) GetPublicKey(data []byte) ([]byte, error) {
	saveData := &keygen.LocalPartySaveData{}
	err := json.Unmarshal(data, saveData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal save data: %w", err)
	}

	if saveData.EDDSAPub == nil {
		return nil, errors.New("EDDSA public key is nil")
	}

	publicKey := saveData.EDDSAPub
	pubKey := &edwards.PublicKey{
		Curve: publicKey.Curve(),
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}

	pubKeyBytes := pubKey.SerializeCompressed()
	return pubKeyBytes, nil
}

func (s *EDDSASession) VerifySignature(msg []byte, signature []byte) (*common.SignatureData, error) {
	signatureData := &common.SignatureData{}
	err := json.Unmarshal(signature, signatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature data: %w", err)
	}

	data := s.party.GetSaveData()
	if data == nil {
		return nil, errors.New("save data is nil")
	}

	saveData := &keygen.LocalPartySaveData{}
	err = json.Unmarshal(data, saveData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal save data: %w", err)
	}

	if saveData.EDDSAPub == nil {
		return nil, errors.New("EDDSA public key is nil")
	}

	publicKey := saveData.EDDSAPub
	pk := &edwards.PublicKey{
		Curve: publicKey.Curve(),
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}

	// Convert signature components to big integers
	r := new(big.Int).SetBytes(signatureData.R)
	sigS := new(big.Int).SetBytes(signatureData.S)

	// Verify the signature
	ok := edwards.Verify(pk, msg, r, sigS)
	if !ok {
		return nil, errors.New("signature verification failed")
	}

	return signatureData, nil
}
