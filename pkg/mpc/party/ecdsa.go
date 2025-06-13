package party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type ECDSAParty struct {
	party
	preParams keygen.LocalPreParams
	saveData  *keygen.LocalPartySaveData
}

func NewECDSAParty(walletID string, partyID *tss.PartyID, partyIDs []*tss.PartyID, threshold int,
	preParams keygen.LocalPreParams, errCh chan error) *ECDSAParty {
	return &ECDSAParty{
		party:     *NewParty(walletID, partyID, partyIDs, threshold, errCh),
		preParams: preParams,
	}
}

func (s *ECDSAParty) GetSaveData() []byte {
	saveData, err := json.Marshal(s.saveData)
	if err != nil {
		s.ErrCh() <- fmt.Errorf("failed serializing shares: %w", err)
		return nil
	}
	return saveData
}

func (s *ECDSAParty) SetSaveData(saveData []byte) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(saveData, &localSaveData)
	if err != nil {
		s.ErrCh() <- fmt.Errorf("failed deserializing shares: %w", err)
		return
	}
	s.saveData = &localSaveData
}

func (s *ECDSAParty) StartKeygen(ctx context.Context, send func(tss.Message), finish func([]byte)) {
	end := make(chan *keygen.LocalPartySaveData, 1)
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(s.partyIDs), s.partyID, len(s.partyIDs), s.threshold)
	party := keygen.NewLocalParty(params, s.outCh, end, s.preParams)
	runParty(s, ctx, party, send, end, finish)
}

func (s *ECDSAParty) StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), finish func([]byte)) {
	if s.saveData == nil {
		s.ErrCh() <- errors.New("save data is nil")
		return
	}
	end := make(chan *common.SignatureData, 1)
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(s.partyIDs), s.partyID, len(s.partyIDs), s.threshold)
	party := signing.NewLocalParty(msg, params, *s.saveData, s.outCh, end)
	runParty(s, ctx, party, send, end, finish)
}

func (s *ECDSAParty) StartResharing(ctx context.Context, oldPartyIDs, newPartyIDs []*tss.PartyID,
	oldThreshold, newThreshold int, send func(tss.Message), finish func([]byte)) {
	if s.saveData == nil {
		s.ErrCh() <- errors.New("save data is nil")
		return
	}
	end := make(chan *keygen.LocalPartySaveData, 1)
	params := tss.NewReSharingParameters(
		tss.S256(),
		tss.NewPeerContext(oldPartyIDs),
		tss.NewPeerContext(newPartyIDs),
		s.partyID,
		len(oldPartyIDs),
		oldThreshold,
		len(newPartyIDs),
		newThreshold,
	)
	party := resharing.NewLocalParty(params, *s.saveData, s.outCh, end)
	runParty(s, ctx, party, send, end, finish)
}
