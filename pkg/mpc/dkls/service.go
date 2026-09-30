//go:build dkls

package dkls

import (
	"fmt"
	"slices"
	"sync"

	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
)

type PeerRegistry interface {
	ArePeersReady() bool
	GetReadyPeersIncludeSelf() []string
}

type Identity interface {
	MessageAuthenticator
	MessageCipher
}

type Config struct {
	NodeID   string
	PubSub   messaging.PubSub
	Identity Identity
	KV       kvstore.KVStore
	KeyInfo  keyinfo.Store
	Peers    PeerRegistry
}

type Service struct {
	cfg    Config
	router *Router
	keys   KeyShareStore
}

// Start it before the node is marked ready so peers never publish to an unsubscribed node.
func NewService(cfg Config) (*Service, error) {
	router, err := NewRouter(cfg.NodeID, cfg.PubSub, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("start dkls router: %w", err)
	}
	return &Service{cfg: cfg, router: router, keys: NewKeyStore(cfg.KV, cfg.KeyInfo)}, nil
}

func (s *Service) Close() { s.router.Close() }

func (s *Service) Keygen(walletID string, threshold int) (KeyResult, error) {
	if !s.cfg.Peers.ArePeersReady() {
		return KeyResult{}, ErrPeersNotReady
	}
	if _, err := s.keys.Info(walletID); err == nil {
		return KeyResult{}, fmt.Errorf("%w: %s", ErrKeyExists, walletID)
	}

	sess, err := s.newSession(walletID, walletID, ActKeygen, s.cfg.Peers.GetReadyPeersIncludeSelf(), threshold)
	if err != nil {
		return KeyResult{}, err
	}
	defer sess.Close()
	return sess.Keygen()
}

func (s *Service) Sign(walletID, txID string, msgHash []byte, derivationPath []uint32) (Signature, error) {
	info, err := s.keys.Info(walletID)
	if err != nil {
		return Signature{}, err
	}
	if !slices.Contains(info.ParticipantPeerIDs, s.cfg.NodeID) {
		return Signature{}, ErrNotParticipant
	}

	ready := s.cfg.Peers.GetReadyPeersIncludeSelf()
	var readyParticipants []string
	for _, id := range info.ParticipantPeerIDs {
		if slices.Contains(ready, id) {
			readyParticipants = append(readyParticipants, id)
		}
	}
	if len(readyParticipants) < info.Threshold+1 {
		return Signature{}, fmt.Errorf("%w: need %d, have %d", ErrNotEnoughSigners, info.Threshold+1, len(readyParticipants))
	}
	signers := readyParticipants[:info.Threshold+1]
	if !slices.Contains(signers, s.cfg.NodeID) {
		return Signature{}, ErrNotSelected
	}

	sess, err := s.newSession(walletID, walletID+":"+txID, ActSign, info.ParticipantPeerIDs, info.Threshold)
	if err != nil {
		return Signature{}, err
	}
	defer sess.Close()
	return sess.Sign(msgHash, signers, derivationPath)
}

func (s *Service) newSession(walletID, sessionKey string, act Act, participants []string, threshold int) (*Session, error) {
	return NewSession(SessionConfig{
		WalletID:     walletID,
		SelfNodeID:   s.cfg.NodeID,
		Participants: participants,
		Threshold:    threshold,
		SessionKey:   sessionKey,
		Transport:    NewNATSTransport(sessionKey, act, s.router, s.cfg.PubSub, s.cfg.Identity),
		Cipher:       s.cfg.Identity,
		Keys:         s.keys,
	})
}

type KeyShareStore interface {
	LoadShare(walletID string) ([]byte, error)
	Save(walletID string, share []byte, info *keyinfo.KeyInfo) error
	Info(walletID string) (*keyinfo.KeyInfo, error)
}

type keyStore struct {
	kv    kvstore.KVStore
	info  keyinfo.Store
	cache sync.Map
}

func NewKeyStore(kv kvstore.KVStore, info keyinfo.Store) KeyShareStore {
	return &keyStore{kv: kv, info: info}
}

func keyID(walletID string) string { return "dkls:" + walletID }

func (s *keyStore) LoadShare(walletID string) ([]byte, error) {
	return s.kv.Get(keyID(walletID))
}

func (s *keyStore) Save(walletID string, share []byte, info *keyinfo.KeyInfo) error {
	if err := s.kv.Put(keyID(walletID), share); err != nil {
		return fmt.Errorf("store key share: %w", err)
	}
	if err := s.info.Save(keyID(walletID), info); err != nil {
		return fmt.Errorf("store key info: %w", err)
	}
	s.cache.Store(walletID, info)
	return nil
}

// Cached because participants and threshold never change after keygen.
func (s *keyStore) Info(walletID string) (*keyinfo.KeyInfo, error) {
	if cached, ok := s.cache.Load(walletID); ok {
		return cached.(*keyinfo.KeyInfo), nil
	}
	info, err := s.info.Get(keyID(walletID))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWalletNotFound, err)
	}
	s.cache.Store(walletID, info)
	return info, nil
}
