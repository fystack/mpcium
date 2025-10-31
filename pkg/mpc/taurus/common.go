package taurus

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/mpc/ckd"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type Protocol string

const (
	CGGMP21      Protocol = "cggmp21-ecdsa" // Canetti et al. 2021 (CMP)
	FROST        Protocol = "frost-schnorr" // FROST Schnorr signatures
	FROSTTaproot Protocol = "frost-taproot" // FROST for Bitcoin Taproot
)

func (p Protocol) String() string {
	return string(p)
}

type TaurusSession interface {
	LoadKey(sid string) error
	Keygen(ctx context.Context) (types.KeyData, error)
	Sign(ctx context.Context, msg *big.Int, derivationPath []uint32) ([]byte, error)
	Reshare(ctx context.Context) (types.ReshareData, error)
	Presign(ctx context.Context, txID string, derivationPath []uint32) (bool, error)
}

type commonSession struct {
	sessionID    string
	threshold    int
	selfID       party.ID
	peerIDs      party.IDSlice
	network      *NetworkAdapter
	kvstore      kvstore.KVStore
	keyinfoStore keyinfo.Store
	ckd          *ckd.CKD
}

func NewCommonSession(
	sessionID string,
	selfID party.ID,
	peerIDs party.IDSlice,
	threshold int,
	transport Transport,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	ckd *ckd.CKD,
) *commonSession {
	net := NewNetworkAdapter(sessionID, selfID, transport, peerIDs)
	return &commonSession{
		sessionID:    sessionID,
		selfID:       selfID,
		peerIDs:      peerIDs,
		threshold:    threshold,
		network:      net,
		kvstore:      kvstore,
		keyinfoStore: keyinfoStore,
		ckd:          ckd,
	}
}

func (p *commonSession) Presign(ctx context.Context, txID string, derivationPath []uint32) (bool, error) {
	return false, errors.New("not implemented")
}

func (p *commonSession) run(ctx context.Context, proto protocol.StartFunc) (any, error) {
	h, err := protocol.NewMultiHandler(proto, []byte(p.sessionID))
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg, ok := <-h.Listen():
			if !ok {
				return h.Result()
			}
			go p.network.Send(msg)
		case msg := <-p.network.Next():
			if h.CanAccept(msg) {
				h.Accept(msg)
			}
		}
	}
}

func (p *commonSession) getParticipantPeerIDs() []string {
	var ids []string
	for _, id := range p.peerIDs {
		ids = append(ids, string(id))
	}
	return ids
}

func extractPublicKey(pubPoint curve.Point) (*big.Int, *big.Int, error) {
	if pubPoint == nil {
		return nil, nil, errors.New("nil public point")
	}

	data, err := pubPoint.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	if len(data) == 0 {
		return nil, nil, errors.New("empty public key data")
	}

	// Use btcec's ParsePubKey which handles both compressed and uncompressed formats
	pubKey, err := btcec.ParsePubKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	// Extract x and y coordinates
	x := pubKey.X()
	y := pubKey.Y()

	return x, y, nil
}
