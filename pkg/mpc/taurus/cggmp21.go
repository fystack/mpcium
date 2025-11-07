package taurus

import (
	"context"
	cryptoEcdsa "crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/presigninfo"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

type CGGMP21Session struct {
	*commonSession
	workerPool       *pool.Pool
	savedData        *cmp.Config
	presignInfoStore presigninfo.Store
}

func NewCGGMP21Session(
	sessionID string,
	selfID party.ID,
	peerIDs party.IDSlice,
	threshold int,
	presignInfoStore presigninfo.Store,
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
		commonSession:    commonSession,
		workerPool:       pool.NewPool(0),
		savedData:        nil,
		presignInfoStore: presignInfoStore,
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
	logger.Info("Starting CGGMP21 sign", "walletID", p.sessionID)

	msgHash := msg.Bytes()
	var (
		sigResult any
		err       error
	)

	// Try presign path if store available
	if p.presignInfoStore != nil {
		sigResult, err = p.signWithPresign(ctx, msgHash)
	} else {
		sigResult, err = p.signFull(ctx, msgHash)
	}
	if err != nil {
		return nil, err
	}

	// Cast and verify
	sig, ok := sigResult.(*ecdsa.Signature)
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
	// Store presign in KV using deterministic key including txID
	packed, err := cbor.Marshal(presig)
	if err != nil {
		return false, fmt.Errorf("marshal presign: %w", err)
	}
	if err := p.kvstore.Put(p.composePresignKey(p.sessionID, txID), packed); err != nil {
		return false, fmt.Errorf("store presign: %w", err)
	}
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

func (p *CGGMP21Session) composePresignKey(sid, txID string) string {
	return fmt.Sprintf("cggmp21:%s:%s", sid, txID)
}

// signWithPresign tries to select and use an existing presign for signing.
// If no valid presign exists, falls back to full sign.
func (p *CGGMP21Session) signWithPresign(ctx context.Context, msgHash []byte) (any, error) {
	presig, txID := p.selectAndLoadPresign()
	if presig == nil || txID == "" {
		logger.Debug("No presign found, fallback to full sign", "walletID", p.sessionID)
		return p.signFull(ctx, msgHash)
	}

	logger.Info("Using presign for signing", "walletID", p.sessionID, "txID", txID)
	result, err := p.run(ctx, cmp.PresignOnline(p.savedData, presig, msgHash, p.workerPool))
	if err != nil {
		return nil, fmt.Errorf("presign online failed: %w", err)
	}

	// Mark and cleanup in background (best effort)
	go func() {
		if err := p.markPresignUsed(txID); err != nil {
			logger.Warn("mark presign used failed", "walletID", p.sessionID, "txID", txID, "err", err)
		}
		if err := p.deletePresign(txID); err != nil {
			logger.Warn("delete presign failed", "walletID", p.sessionID, "txID", txID, "err", err)
		}
	}()

	return result, nil
}

// signFull executes a full CGGMP21 signing round.
func (p *CGGMP21Session) signFull(ctx context.Context, msgHash []byte) (any, error) {
	logger.Info("Executing full CGGMP21 signing", "walletID", p.sessionID)
	result, err := p.run(ctx, cmp.Sign(p.savedData, p.peerIDs, msgHash, p.workerPool))
	if err != nil {
		return nil, fmt.Errorf("full sign failed: %w", err)
	}
	return result, nil
}

func (p *CGGMP21Session) selectAndLoadPresign() (*ecdsa.PreSignature, string) {
	infos, err := p.presignInfoStore.ListPendingPresigns(p.sessionID)
	if err != nil || len(infos) == 0 {
		return nil, ""
	}

	// Filter usable presigns
	var filtered []*presigninfo.PresignInfo
	for _, inf := range infos {
		if inf.Status == presigninfo.PresignStatusActive &&
			inf.Protocol == types.ProtocolCGGMP21 &&
			inf.KeyType == types.KeyTypeSecp256k1 {
			filtered = append(filtered, inf)
		}
	}
	if len(filtered) == 0 {
		return nil, ""
	}

	// Sort + pick deterministically
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].CreatedAt.Equal(filtered[j].CreatedAt) {
			return filtered[i].TxID < filtered[j].TxID
		}
		return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
	})
	h := sha256.Sum256([]byte(p.sessionID))
	idx := int(binary.BigEndian.Uint64(h[:8]) % uint64(len(filtered)))
	chosen := filtered[idx]

	// Load presign from KV
	key := p.composePresignKey(p.sessionID, chosen.TxID)
	data, err := p.kvstore.Get(key)
	if err != nil || len(data) == 0 {
		logger.Warn("presign missing", "walletID", p.sessionID, "txID", chosen.TxID, "err", err)
		return nil, ""
	}

	presig := ecdsa.EmptyPreSignature(curve.Secp256k1{})
	if err := cbor.Unmarshal(data, presig); err != nil {
		logger.Warn("unmarshal presign failed", "walletID", p.sessionID, "txID", chosen.TxID, "err", err)
		return nil, ""
	}
	if err := presig.Validate(); err != nil {
		logger.Warn("presign invalid", "walletID", p.sessionID, "txID", chosen.TxID, "err", err)
		return nil, ""
	}

	logger.Debug("Presign chosen", "walletID", p.sessionID, "txID", chosen.TxID, "idx", idx)
	return presig, chosen.TxID
}

func (p *CGGMP21Session) markPresignUsed(txID string) error {
	info, err := p.presignInfoStore.Get(p.sessionID, txID)
	if err != nil {
		return err
	}
	now := time.Now()
	info.Status = presigninfo.PresignStatusUsed
	info.UsedAt = &now
	return p.presignInfoStore.Save(p.sessionID, info)
}

func (p *CGGMP21Session) deletePresign(txID string) error {
	return p.kvstore.Delete(p.composePresignKey(p.sessionID, txID))
}
