package taurus

import (
	"context"
	cryptoEcdsa "crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/mpc/ckd"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

type TaprootSession struct {
	*commonSession
	savedData *frost.TaprootConfig
}

func NewTaprootSession(
	sessionID string,
	selfID party.ID,
	peerIDs party.IDSlice,
	threshold int,
	transport Transport,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	ckd *ckd.CKD,
) TaurusSession {
	commonSession := NewCommonSession(
		sessionID,
		selfID,
		peerIDs,
		threshold,
		transport,
		kvstore,
		keyinfoStore,
		ckd,
	)
	return &TaprootSession{
		commonSession: commonSession,
		savedData:     nil,
	}
}

func (p *TaprootSession) LoadKey(sid string) error {
	key := p.composeKey(sid)

	data, err := p.kvstore.Get(key)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	cfg := &frost.TaprootConfig{}
	if err := cbor.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("unmarshal key config: %w", err)
	}

	p.savedData = cfg
	return nil
}

func (p *TaprootSession) Keygen(ctx context.Context) (types.KeyData, error) {
	logger.Info("Starting to generate key Taproot", "walletID", p.sessionID)

	result, err := p.run(ctx, frost.KeygenTaproot(p.selfID, p.peerIDs, p.threshold))
	if err != nil {
		return types.KeyData{}, err
	}

	cfg, ok := result.(*frost.TaprootConfig)
	if !ok {
		return types.KeyData{}, fmt.Errorf("unexpected result type %T", result)
	}
	p.savedData = cfg

	pubPoint, err := curve.Secp256k1{}.LiftX(cfg.PublicKey)
	if err != nil {
		return types.KeyData{}, fmt.Errorf("lift pubkey: %w", err)
	}
	// Extract public key coordinates
	x, y, err := extractPublicKey(pubPoint)
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

	packed, err := cbor.Marshal(cfg)
	if err != nil {
		return types.KeyData{}, fmt.Errorf("marshal config: %w", err)
	}

	key := p.composeKey(p.sessionID)
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
		SID:         p.sessionID,
		Type:        FROSTTaproot.String(),
		PubKeyBytes: pubKeyBytes,
	}, nil
}

func (p *TaprootSession) Sign(ctx context.Context, msg *big.Int, derivationPath []uint32) ([]byte, error) {
	if p.savedData == nil {
		return nil, errors.New("no key loaded")
	}
	for _, path := range derivationPath {
		cfg, err := p.savedData.DeriveChild(path)
		if err != nil {
			return nil, err
		}
		p.savedData = cfg
	}
	logger.Info("Starting to sign message Taproot", "walletID", p.sessionID)
	msgHash := msg.Bytes()
	result, err := p.run(ctx, frost.SignTaproot(p.savedData, p.peerIDs, msgHash))
	if err != nil {
		return nil, err
	}
	sig, ok := result.(taproot.Signature)
	if !ok {
		return nil, errors.New("unexpected result type")
	}
	if !p.savedData.PublicKey.Verify(sig, msgHash) {
		return nil, errors.New("signature verification failed")
	}
	return []byte(sig), nil
}

func (p *TaprootSession) Reshare(ctx context.Context) (res types.ReshareData, err error) {
	if p.savedData == nil {
		return res, errors.New("no key loaded")
	}
	cfg, err := p.run(ctx, frost.RefreshTaproot(p.savedData, p.peerIDs))
	if err != nil {
		return res, err
	}
	savedData, ok := cfg.(*frost.TaprootConfig)
	if !ok {
		return res, errors.New("unexpected result type")
	}
	p.savedData = savedData
	packed, err := cbor.Marshal(p.savedData)
	if err != nil {
		return res, fmt.Errorf("marshal config: %w", err)
	}

	key := p.composeKey(p.sessionID)
	// Store updated key share
	if p.kvstore != nil {
		if err := p.kvstore.Put(key, packed); err != nil {
			return res, fmt.Errorf("store key: %w", err)
		}
	}

	// Extract public key coordinates
	pubPoint, err := curve.Secp256k1{}.LiftX(p.savedData.PublicKey)
	if err != nil {
		return res, fmt.Errorf("lift pubkey: %w", err)
	}
	x, y, err := extractPublicKey(pubPoint)
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

	return types.ReshareData{
		KeyData: types.KeyData{
			SID:         p.sessionID,
			Type:        CGGMP21.String(),
			PubKeyBytes: pubKeyBytes,
		},
		Threshold: p.threshold,
	}, nil
}

func (p *TaprootSession) composeKey(sid string) string {
	return fmt.Sprintf("taproot:%s", sid)
}
