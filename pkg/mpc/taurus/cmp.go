package taurus

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

type CmpParty struct {
	sid       string
	id        party.ID
	ids       party.IDSlice
	threshold int
	pl        *pool.Pool
	savedData *cmp.Config
	network   NetworkInterface
}

func NewCmpParty(
	sid string,
	id party.ID,
	ids party.IDSlice,
	threshold int,
	pl *pool.Pool,
	network NetworkInterface,
) *CmpParty {
	return &CmpParty{
		sid:       sid,
		id:        id,
		ids:       ids,
		threshold: threshold,
		pl:        pl,
		network:   network,
	}
}

func (p *CmpParty) LoadKey(data *types.KeyData) error {
	cfg := cmp.EmptyConfig(curve.Secp256k1{})
	if err := cfg.UnmarshalBinary(data.Payload); err != nil {
		return fmt.Errorf("decode key data: %w", err)
	}
	p.savedData = cfg
	return nil
}

func (p *CmpParty) Keygen(ctx context.Context) (types.KeyData, error) {
	h, err := protocol.NewMultiHandler(
		cmp.Keygen(curve.Secp256k1{}, p.id, p.ids, p.threshold, p.pl),
		[]byte(p.sid),
	)
	if err != nil {
		return types.KeyData{}, err
	}
	if err := p.executeProtocol(ctx, h); err != nil {
		return types.KeyData{}, err
	}
	res, err := h.Result()
	if err != nil {
		return types.KeyData{}, err
	}
	cfg, ok := res.(*cmp.Config)
	if !ok {
		return types.KeyData{}, errors.New("unexpected result type")
	}
	p.savedData = cfg
	packed, _ := cfg.MarshalBinary()
	return types.KeyData{SID: p.sid, Type: "taurus_cmp", Payload: packed}, nil
}

func (p *CmpParty) Sign(ctx context.Context, msg *big.Int) ([]byte, error) {
	if p.savedData == nil {
		return nil, errors.New("no key loaded")
	}
	h, err := protocol.NewMultiHandler(
		cmp.Sign(p.savedData, p.ids, msg.Bytes(), p.pl),
		[]byte(p.sid),
	)
	if err != nil {
		return nil, err
	}
	if err := p.executeProtocol(ctx, h); err != nil {
		return nil, err
	}
	res, err := h.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := res.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("unexpected signature result")
	}
	if !sig.Verify(p.savedData.PublicPoint(), msg.Bytes()) {
		return nil, errors.New("failed to verify cmp signature")
	}
	return sig.SigEthereum()
}

func (p *CmpParty) Reshare(ctx context.Context) (types.KeyData, error) {
	if p.savedData == nil {
		return types.KeyData{}, errors.New("no key loaded")
	}
	h, err := protocol.NewMultiHandler(cmp.Refresh(p.savedData, p.pl), []byte(p.sid))
	if err != nil {
		return types.KeyData{}, err
	}
	if err := p.executeProtocol(ctx, h); err != nil {
		return types.KeyData{}, err
	}
	res, err := h.Result()
	if err != nil {
		return types.KeyData{}, err
	}
	cfg, ok := res.(*cmp.Config)
	if !ok {
		return types.KeyData{}, errors.New("unexpected result type")
	}
	p.savedData = cfg
	packed, _ := cfg.MarshalBinary()
	return types.KeyData{SID: p.sid, Type: "taurus_cmp", Payload: packed}, nil
}

func (p *CmpParty) executeProtocol(ctx context.Context, h protocol.Handler) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-h.Listen():
			if !ok {
				return nil
			}
			p.network.Send(msg)
		case msg := <-p.network.Next():
			if h.CanAccept(msg) {
				h.Accept(msg)
			} else {
				logger.Warn("⚠️ Ignored invalid msg", "self", p.id)
			}
		case <-p.network.Done():
			return nil
		}
	}
}
