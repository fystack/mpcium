package taurus

import (
	"context"
	cryptoEcdsa "crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

type CGGMP21Session struct {
	*commonSession
	workerPool   *pool.Pool
	savedData    *cmp.Config
	presignCache *PresignCache
}

func NewCGGMP21Session(
	sessionID string,
	selfID party.ID,
	peerIDs party.IDSlice,
	threshold int,
	presignCache *PresignCache,
	transport Transport,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
) TaurusSession {
	commonSession := NewCommonSession(
		sessionID,
		selfID,
		peerIDs,
		threshold,
		transport,
		kvstore,
		keyinfoStore,
	)
	return &CGGMP21Session{
		commonSession: commonSession,
		workerPool:    pool.NewPool(0),
		savedData:     nil,
		presignCache:  presignCache,
	}
}

func (p *CGGMP21Session) LoadKey(sid string) error {
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

func (p *CGGMP21Session) Keygen(ctx context.Context) (types.KeyData, error) {
	logger.Info("Starting to generate key CGGMP21", "walletID", p.sessionID)

	result, err := p.run(
		ctx,
		cmp.Keygen(curve.Secp256k1{}, p.selfID, p.peerIDs, p.threshold, p.workerPool),
	)
	if err != nil {
		return types.KeyData{}, err
	}

	cfg, ok := result.(*cmp.Config)
	if !ok {
		return types.KeyData{}, fmt.Errorf("unexpected result type %T", result)
	}
	p.savedData = cfg

	packed, err := cfg.MarshalBinary()
	if err != nil {
		return types.KeyData{}, fmt.Errorf("marshal config: %w", err)
	}

	x, y, err := extractPublicKey(cfg.PublicPoint())
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
		Type:        CGGMP21.String(),
		PubKeyBytes: pubKeyBytes,
	}, nil
}

func (p *CGGMP21Session) Sign(ctx context.Context, msg *big.Int) ([]byte, error) {
	if p.savedData == nil {
		return nil, errors.New("no key loaded")
	}

	logger.Info("starting CGGMP21 sign", "walletID", p.sessionID)
	msgHash := msg.Bytes()

	var (
		result any
		err    error
	)

	if presign := p.getCachedPresign(); presign != nil {
		result, err = p.run(ctx, cmp.PresignOnline(p.savedData, presign, msgHash, p.workerPool))
		if err != nil {
			return nil, fmt.Errorf("presign online failed: %w", err)
		}
	} else {
		result, err = p.run(ctx, cmp.Sign(p.savedData, p.peerIDs, msgHash, p.workerPool))
		if err != nil {
			return nil, fmt.Errorf("full sign failed: %w", err)
		}
	}

	sig, ok := result.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("unexpected result type")
	}
	if !sig.Verify(p.savedData.PublicPoint(), msgHash) {
		return nil, errors.New("signature verification failed")
	}
	return sig.SigEthereum()
}

func (p *CGGMP21Session) Presign(ctx context.Context, txID string) (bool, error) {
	if p.savedData == nil {
		return false, errors.New("no key loaded")
	}
	logger.Info("Starting to presign message CGGMP21", "walletID", p.sessionID, "txID", txID)
	result, err := p.run(ctx, cmp.Presign(p.savedData, p.peerIDs, p.workerPool))
	if err != nil {
		return false, err
	}
	presig, ok := result.(*ecdsa.PreSignature)
	if !ok {
		return false, errors.New("unexpected result type")
	}
	if err = presig.Validate(); err != nil {
		return false, errors.New("presign validation failed")
	}

	p.presignCache.Put(p.sessionID, txID, presig)
	return true, nil
}

func (p *CGGMP21Session) Reshare(ctx context.Context) (res types.ReshareData, err error) {
	if p.savedData == nil {
		return res, errors.New("no key loaded")
	}
	cfg, err := p.run(ctx, cmp.Refresh(p.savedData, p.workerPool))
	if err != nil {
		return res, err
	}
	savedData, ok := cfg.(*cmp.Config)
	if !ok {
		return res, errors.New("unexpected result type")
	}
	p.savedData = savedData
	packed, _ := p.savedData.MarshalBinary()

	key := p.composeKey(p.sessionID)
	// Store updated key share
	if p.kvstore != nil {
		if err := p.kvstore.Put(key, packed); err != nil {
			return res, fmt.Errorf("store key: %w", err)
		}
	}

	// Extract public key coordinates
	x, y, err := extractPublicKey(p.savedData.PublicPoint())
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

func (p *CGGMP21Session) composeKey(sid string) string {
	return fmt.Sprintf("cggmp21:%s", sid)
}

func (p *CGGMP21Session) getCachedPresign() *ecdsa.PreSignature {
	if p.presignCache == nil {
		return nil
	}

	presig, ok := p.presignCache.Get(p.sessionID)
	if !ok || presig == nil {
		return nil
	}

	return presig
}
