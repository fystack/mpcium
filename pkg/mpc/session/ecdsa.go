package session

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/party"
)

type ECDSASession struct {
	*session
}

func NewECDSASession(walletID string, partyID *tss.PartyID, partyIDs []*tss.PartyID, threshold int, preParams keygen.LocalPreParams, pubSub messaging.PubSub, direct messaging.DirectMessaging, identityStore identity.Store, kvstore kvstore.KVStore, keyinfoStore keyinfo.Store) *ECDSASession {
	s := NewSession(PurposeKeygen, walletID, pubSub, direct, identityStore, kvstore, keyinfoStore)
	s.party = party.NewECDSAParty(walletID, partyID, partyIDs, threshold, preParams, s.errCh)
	s.topicComposer = &TopicComposer{
		ComposeBroadcastTopic: func() string {
			return fmt.Sprintf("broadcast:ecdsa:%s", walletID)
		},
		ComposeDirectTopic: func(nodeID string) string {
			return fmt.Sprintf("direct:ecdsa:%s:%s", nodeID, walletID)
		},
	}
	s.composeKey = func(walletID string) string {
		return fmt.Sprintf("ecdsa:%s", walletID)
	}
	return &ECDSASession{
		session: s,
	}
}

func (s *ECDSASession) StartKeygen(ctx context.Context, send func(tss.Message), finish func([]byte)) {
	s.party.StartKeygen(ctx, send, finish)
}

func (s *ECDSASession) StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), finish func([]byte)) {
	s.party.StartSigning(ctx, msg, send, finish)
}

func (s *ECDSASession) StartResharing(ctx context.Context, oldPartyIDs []*tss.PartyID, newPartyIDs []*tss.PartyID, oldThreshold int, newThreshold int, send func(tss.Message), finish func([]byte)) {
	s.party.StartResharing(ctx, oldPartyIDs, newPartyIDs, oldThreshold, newThreshold, send, finish)
}

func (s *ECDSASession) GetPublicKey(data []byte) ([]byte, error) {
	saveData := &keygen.LocalPartySaveData{}
	err := json.Unmarshal(data, saveData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal save data: %w", err)
	}
	publicKey := saveData.ECDSAPub
	pubKey := &ecdsa.PublicKey{
		Curve: publicKey.Curve(),
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}
	pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	return pubKeyBytes, nil
}

func (s *ECDSASession) VerifySignature(msg []byte, signature []byte) (*common.SignatureData, error) {
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

	if saveData.ECDSAPub == nil {
		return nil, errors.New("ECDSA public key is nil")
	}

	publicKey := saveData.ECDSAPub
	pk := &ecdsa.PublicKey{
		Curve: publicKey.Curve(),
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}

	// Convert signature components to big integers
	r := new(big.Int).SetBytes(signatureData.R)
	sigS := new(big.Int).SetBytes(signatureData.S)

	// Verify the signature
	ok := ecdsa.Verify(pk, msg, r, sigS)
	if !ok {
		return nil, errors.New("signature verification failed")
	}

	return signatureData, nil
}
