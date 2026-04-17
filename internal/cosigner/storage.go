package cosigner

import (
	"fmt"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type PreparamsStore interface {
	LoadPreparams(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error)
	SavePreparams(protocolType sdkprotocol.ProtocolType, keyID string, preparams []byte) error
}

type SharesStore interface {
	LoadShare(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error)
	SaveShare(protocolType sdkprotocol.ProtocolType, keyID string, share []byte) error
}

type SessionArtifactsStore interface {
	LoadSessionArtifacts(sessionID string) ([]byte, error)
	SaveSessionArtifacts(sessionID string, artifact []byte) error
	DeleteSessionArtifacts(sessionID string) error
}

type Stores interface {
	PreparamsStore
	SharesStore
	SessionArtifactsStore
	Close() error
}

type badgerStores struct {
	db *badger.DB
}

func newBadgerStores(dataDir string) (*badgerStores, error) {
	opts := badger.DefaultOptions(filepath.Join(dataDir, "node-v1-badger"))
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &badgerStores{db: db}, nil
}

func (s *badgerStores) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *badgerStores) LoadPreparams(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error) {
	return s.load(keyPreparams(protocolType, keyID))
}

func (s *badgerStores) SavePreparams(protocolType sdkprotocol.ProtocolType, keyID string, preparams []byte) error {
	return s.save(keyPreparams(protocolType, keyID), preparams)
}

func (s *badgerStores) LoadShare(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error) {
	return s.load(keyShare(protocolType, keyID))
}

func (s *badgerStores) SaveShare(protocolType sdkprotocol.ProtocolType, keyID string, share []byte) error {
	return s.save(keyShare(protocolType, keyID), share)
}

func (s *badgerStores) LoadSessionArtifacts(sessionID string) ([]byte, error) {
	return s.load(keyArtifact(sessionID))
}

func (s *badgerStores) SaveSessionArtifacts(sessionID string, artifact []byte) error {
	return s.save(keyArtifact(sessionID), artifact)
}

func (s *badgerStores) DeleteSessionArtifacts(sessionID string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(keyArtifact(sessionID)))
	})
}

func (s *badgerStores) load(key string) ([]byte, error) {
	var value []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				value = nil
				return nil
			}
			return err
		}
		return item.Value(func(v []byte) error {
			value = append([]byte(nil), v...)
			return nil
		})
	})
	return value, err
}

func (s *badgerStores) save(key string, value []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), append([]byte(nil), value...))
	})
}

func keyPreparams(protocolType sdkprotocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("preparams:%s:%s", protocolType, keyID)
}

func keyShare(protocolType sdkprotocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("shares:%s:%s", protocolType, keyID)
}

func keyArtifact(sessionID string) string {
	return "artifacts:" + sessionID
}
