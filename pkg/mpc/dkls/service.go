//go:build dkls

package dkls

import (
	"fmt"
	"slices"
	"sync"
	"time"

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

const (
	shareWaitTimeout  = 10 * time.Second
	sharePollInterval = 50 * time.Millisecond
)

type Service struct {
	cfg    Config
	router *Router
	keys   KeyShareStore
	locks  sync.Map
}

// A refresh rewrites the share, so signing with a half-rotated committee fails; refresh excludes signs per wallet.
func (s *Service) walletLock(walletID string) *sync.RWMutex {
	lock, _ := s.locks.LoadOrStore(walletID, &sync.RWMutex{})
	return lock.(*sync.RWMutex)
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

func (s *Service) Refresh(walletID, refreshID string) (KeyResult, error) {
	info, err := s.keys.Info(walletID)
	if err != nil {
		return KeyResult{}, err
	}
	if !slices.Contains(info.ParticipantPeerIDs, s.cfg.NodeID) {
		return KeyResult{}, ErrNotParticipant
	}
	ready := s.cfg.Peers.GetReadyPeersIncludeSelf()
	for _, id := range info.ParticipantPeerIDs {
		if !slices.Contains(ready, id) {
			return KeyResult{}, fmt.Errorf("%w: %s", ErrPeersNotReady, id)
		}
	}
	lock := s.walletLock(walletID)
	lock.Lock()
	defer lock.Unlock()
	if err := s.waitForShare(walletID, shareWaitTimeout); err != nil {
		return KeyResult{}, err
	}

	sess, err := s.newSession(walletID, walletID+":refresh:"+refreshID, ActRefresh, info.ParticipantPeerIDs, info.Threshold)
	if err != nil {
		return KeyResult{}, err
	}
	defer sess.Close()
	return sess.Refresh()
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

	lock := s.walletLock(walletID)
	lock.RLock()
	defer lock.RUnlock()
	if err := s.waitForShare(walletID, shareWaitTimeout); err != nil {
		return Signature{}, err
	}

	sess, err := s.newSession(walletID, walletID+":"+txID, ActSign, info.ParticipantPeerIDs, info.Threshold)
	if err != nil {
		return Signature{}, err
	}
	defer sess.Close()
	return sess.Sign(msgHash, signers, derivationPath)
}

// Key info lives in shared Consul but shares are local, so a sign can arrive before this node's keygen has saved its share.
func (s *Service) waitForShare(walletID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := s.keys.LoadShare(walletID)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %s: %v", ErrShareNotReady, walletID, err)
		}
		time.Sleep(sharePollInterval)
	}
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
