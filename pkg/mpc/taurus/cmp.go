package taurus

import (
	"context"
	cryptoEcdsa "crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
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
	sid          string
	id           party.ID
	ids          party.IDSlice
	threshold    int
	pl           *pool.Pool
	savedData    *cmp.Config
	kvstore      kvstore.KVStore
	keyinfoStore keyinfo.Store
	network      NetworkInterface
}

func NewCmpParty(
	sid string,
	id party.ID,
	ids party.IDSlice,
	threshold int,
	pl *pool.Pool,
	network NetworkInterface,
	keyinfoStore keyinfo.Store,
	kvstore kvstore.KVStore,
) *CmpParty {
	return &CmpParty{
		sid:          sid,
		id:           id,
		ids:          ids,
		threshold:    threshold,
		pl:           pl,
		network:      network,
		keyinfoStore: keyinfoStore,
		kvstore:      kvstore,
	}
}
func (p *CmpParty) LoadKey(sid string) error {
	key := p.composeKey(sid)

	data, err := p.kvstore.Get(key)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	cfg := cmp.EmptyConfig(curve.Secp256k1{})
	if err := cfg.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("unmarshal key config: %w", err)
	}

	p.savedData = cfg
	return nil
}

func (p *CmpParty) Keygen(ctx context.Context) (types.KeyData, error) {
	logger.Info("Starting to generate key Taurus CMP", "walletID", p.sid)

	result, err := p.run(ctx, cmp.Keygen(curve.Secp256k1{}, p.id, p.ids, p.threshold, p.pl))
	if err != nil {
		return types.KeyData{}, fmt.Errorf("cmp keygen: %w", err)
	}

	cfg, ok := result.(*cmp.Config)
	if !ok {
		return types.KeyData{}, fmt.Errorf("unexpected result type %T", result)
	}
	p.savedData = cfg

	// Extract public key coordinates
	x, y, err := ExtractXYFromPoint(cfg.PublicPoint())
	if err != nil {
		return types.KeyData{}, fmt.Errorf("extract pubkey: %w", err)
	}

	// Use secp256k1 curve, not P256
	pubKey := &cryptoEcdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}

	pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
	if err != nil {
		return types.KeyData{}, fmt.Errorf("encode pubkey: %w", err)
	}

	packed, err := cfg.MarshalBinary()
	if err != nil {
		return types.KeyData{}, fmt.Errorf("marshal config: %w", err)
	}

	key := p.composeKey(p.sid)
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: p.getParticipantPeerIDs(),
		Threshold:          p.threshold,
		Version:            1,
	}

	// Store both key and metadata if stores available
	if p.kvstore != nil {
		if err := p.kvstore.Put(key, packed); err != nil {
			return types.KeyData{}, fmt.Errorf("store key: %w", err)
		}
	}
	if p.keyinfoStore != nil {
		if err := p.keyinfoStore.Save(key, keyInfo); err != nil {
			return types.KeyData{}, fmt.Errorf("store key info: %w", err)
		}
	}

	return types.KeyData{
		SID:         p.sid,
		Type:        "taurus_cmp",
		PubKeyBytes: pubKeyBytes,
	}, nil
}

func (p *CmpParty) Sign(ctx context.Context, msg *big.Int) ([]byte, error) {
	if p.savedData == nil {
		return nil, errors.New("no key loaded")
	}
	logger.Info("Starting to sign message Taurus CMP", "walletID", p.sid)
	cfg, err := p.run(ctx, cmp.Sign(p.savedData, p.ids, msg.Bytes(), p.pl))
	if err != nil {
		return nil, err
	}
	sig, ok := cfg.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("unexpected result type")
	}
	if !sig.Verify(p.savedData.PublicPoint(), msg.Bytes()) {
		return nil, errors.New("signature verification failed")
	}
	return sig.SigEthereum()
}

func (p *CmpParty) Reshare(ctx context.Context) (res types.ReshareData, err error) {
	if p.savedData == nil {
		return res, errors.New("no key loaded")
	}
	cfg, err := p.run(ctx, cmp.Refresh(p.savedData, p.pl))
	if err != nil {
		return res, err
	}
	savedData, ok := cfg.(*cmp.Config)
	if !ok {
		return res, errors.New("unexpected result type")
	}
	p.savedData = savedData
	packed, _ := p.savedData.MarshalBinary()

	key := p.composeKey(p.sid)
	// Store updated key share
	if p.kvstore != nil {
		if err := p.kvstore.Put(key, packed); err != nil {
			return res, fmt.Errorf("store key: %w", err)
		}
	}

	// Extract public key coordinates
	x, y, err := ExtractXYFromPoint(p.savedData.PublicPoint())
	if err != nil {
		return res, fmt.Errorf("extract pubkey: %w", err)
	}

	// Use secp256k1 curve, not P256
	pubKey := &cryptoEcdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}

	pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
	if err != nil {
		return res, fmt.Errorf("encode pubkey: %w", err)
	}

	return types.ReshareData{KeyData: types.KeyData{SID: p.sid, Type: "taurus_cmp", PubKeyBytes: pubKeyBytes}, Threshold: p.threshold}, nil
}

func (p *CmpParty) run(ctx context.Context, proto protocol.StartFunc) (any, error) {
	logger.Info("Starting to run Taurus CMP", "walletID", p.sid)
	h, err := protocol.NewMultiHandler(proto, []byte(p.sid))
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
			p.network.Send(msg)
		case msg := <-p.network.Next():
			if h.CanAccept(msg) {
				h.Accept(msg)
			} else {
				logger.Debug("Ignored self broadcast msg",
					"self", p.id,
					"from", msg.From,
					"to", msg.To,
					"broadcast", msg.Broadcast,
				)
			}
		case <-p.network.Done():
			return h.Result()
		}
	}
}

func ExtractXYFromPoint(p curve.Point) (*big.Int, *big.Int, error) {
	data, err := p.MarshalBinary() // compressed SEC1 form (33 bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal point: %w", err)
	}
	pk, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse secp256k1 pubkey: %w", err)
	}
	return pk.X(), pk.Y(), nil
}

func (p *CmpParty) getParticipantPeerIDs() []string {
	var ids []string
	for _, id := range p.ids {
		ids = append(ids, string(id))
	}
	return ids
}

func (p *CmpParty) composeKey(sid string) string {
	return fmt.Sprintf("taurus_cmp:%s", sid)
}
