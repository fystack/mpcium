package party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type EDDSAParty struct {
	party
	reshareParams *tss.ReSharingParameters
	saveData      *keygen.LocalPartySaveData
}

func NewEDDSAParty(walletID string, partyID *tss.PartyID, partyIDs []*tss.PartyID, threshold int,
	reshareParams *tss.ReSharingParameters, saveData *keygen.LocalPartySaveData, errCh chan error) *EDDSAParty {
	return &EDDSAParty{
		party:         *NewParty(walletID, partyID, partyIDs, threshold, errCh),
		reshareParams: reshareParams,
		saveData:      saveData,
	}
}

func (s *EDDSAParty) GetSaveData() []byte {
	saveData, err := json.Marshal(s.saveData)
	if err != nil {
		s.ErrCh() <- fmt.Errorf("failed serializing shares: %w", err)
		return nil
	}
	return saveData
}

func (s *EDDSAParty) SetSaveData(shareData []byte) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(shareData, &localSaveData)
	if err != nil {
		s.ErrCh() <- fmt.Errorf("failed deserializing shares: %w", err)
		return
	}
	s.saveData = &localSaveData
}

func (s *EDDSAParty) StartKeygen(ctx context.Context, send func(tss.Message), finish func([]byte)) {
	end := make(chan *keygen.LocalPartySaveData, 1)
	params := tss.NewParameters(tss.Edwards(), tss.NewPeerContext(s.partyIDs), s.partyID, len(s.partyIDs), s.threshold)
	party := keygen.NewLocalParty(params, s.outCh, end)
	runParty(s, ctx, party, send, end, finish)
}

func (s *EDDSAParty) StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), finish func([]byte)) {
	if s.saveData == nil {
		s.ErrCh() <- errors.New("save data is nil")
		return
	}
	end := make(chan *common.SignatureData, 1)
	params := tss.NewParameters(tss.Edwards(), tss.NewPeerContext(s.partyIDs), s.partyID, len(s.partyIDs), s.threshold)
	party := signing.NewLocalParty(msg, params, *s.saveData, s.outCh, end)
	runParty(s, ctx, party, send, end, finish)
}

func (s *EDDSAParty) StartResharing(ctx context.Context, oldPartyIDs, newPartyIDs []*tss.PartyID,
	oldThreshold, newThreshold int, send func(tss.Message), finish func([]byte)) {
	if s.saveData == nil {
		s.ErrCh() <- errors.New("save data is nil")
		return
	}
	end := make(chan *keygen.LocalPartySaveData, 1)
	params := tss.NewReSharingParameters(
		tss.Edwards(),
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
