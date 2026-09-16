package cosigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/dgraph-io/badger/v4"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	sdkstorage "github.com/fystack/mpcium-sdk/storage"
)

type PreparamsStore interface {
	LoadPreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string) ([]byte, error)
	SavePreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string, preparams []byte) error
	LoadActivePreparamsSlot(protocolType sdkprotocol.ProtocolType) (string, error)
	SaveActivePreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string) error
}

type SharesStore interface {
	LoadShare(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error)
	SaveShare(protocolType sdkprotocol.ProtocolType, keyID string, share []byte) error
}

// ShareMetaStore binds a stored share to its owning workspace so an export
// request can be authorized at the node (defense in depth against an
// orchestrator bypass). It is written at keygen completion; legacy shares
// have no record and export fails closed for them.
type ShareMetaStore interface {
	LoadShareWorkspace(protocolType sdkprotocol.ProtocolType, keyID string) (string, error)
	SaveShareWorkspace(protocolType sdkprotocol.ProtocolType, keyID, workspaceID string) error
}

type SessionArtifactsStore interface {
	LoadSessionArtifacts(sessionID string) ([]byte, error)
	SaveSessionArtifacts(sessionID string, artifact []byte) error
	DeleteSessionArtifacts(sessionID string) error
}

type SessionCheckpointStore interface {
	LoadSessionCheckpoint(sessionID string) ([]byte, error)
	SaveSessionCheckpoint(sessionID string, checkpoint []byte) error
	DeleteSessionCheckpoint(sessionID string) error
}

// ShareRotationStore is the durable two-phase commit boundary reshare relies
// on: a reshare stages a replacement/retirement, and only ReshareCommit
// promotes it onto the active share (or deletes it for a retired member).
type ShareRotationStore interface {
	StageShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string, rotation sdkstorage.ShareRotation) error
	CommitShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) error
	AbortShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) error
}

type Stores interface {
	PreparamsStore
	SharesStore
	ShareMetaStore
	ShareRotationStore
	SessionCheckpointStore
	SessionArtifactsStore
	Close() error
}

type badgerStores struct {
	db         *badger.DB
	rotationMu sync.Mutex
}

func newBadgerStores(dataDir string, nodeID string) (*badgerStores, error) {
	opts := badger.DefaultOptions(filepath.Join(dataDir, nodeID))
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

func (s *badgerStores) LoadPreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string) ([]byte, error) {
	return s.load(keyPreparamsSlot(protocolType, slot))
}

func (s *badgerStores) SavePreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string, preparams []byte) error {
	return s.save(keyPreparamsSlot(protocolType, slot), preparams)
}

func (s *badgerStores) LoadActivePreparamsSlot(protocolType sdkprotocol.ProtocolType) (string, error) {
	value, err := s.load(keyPreparamsActiveSlot(protocolType))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (s *badgerStores) SaveActivePreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string) error {
	return s.save(keyPreparamsActiveSlot(protocolType), []byte(slot))
}

func (s *badgerStores) LoadShare(protocolType sdkprotocol.ProtocolType, keyID string) ([]byte, error) {
	return s.load(keyShare(protocolType, keyID))
}

func (s *badgerStores) SaveShare(protocolType sdkprotocol.ProtocolType, keyID string, share []byte) error {
	return s.save(keyShare(protocolType, keyID), share)
}

func (s *badgerStores) LoadShareWorkspace(protocolType sdkprotocol.ProtocolType, keyID string) (string, error) {
	value, err := s.load(keyShareMeta(protocolType, keyID))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (s *badgerStores) SaveShareWorkspace(protocolType sdkprotocol.ProtocolType, keyID, workspaceID string) error {
	return s.save(keyShareMeta(protocolType, keyID), []byte(workspaceID))
}

// StageShareRotation records the pending mutation for (keyID, sessionID). It is
// idempotent: re-staging the same rotation is a no-op, and a conflicting one is
// rejected. Once committed, staging is a no-op so replays stay safe.
func (s *badgerStores) StageShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string, rotation sdkstorage.ShareRotation) error {
	if err := rotation.Validate(); err != nil {
		return err
	}
	if keyID == "" || sessionID == "" {
		return fmt.Errorf("share rotation key_id and session_id are required")
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	pendingKey := keyShareRotationPending(protocolType, keyID, sessionID)
	if marker, err := s.load(keyShareRotationCommitted(protocolType, keyID, sessionID)); err != nil {
		return err
	} else if len(marker) > 0 {
		return s.delete(pendingKey)
	}
	if existingBlob, err := s.load(pendingKey); err != nil {
		return err
	} else if len(existingBlob) > 0 {
		var existing sdkstorage.ShareRotation
		if err := json.Unmarshal(existingBlob, &existing); err != nil {
			return fmt.Errorf("decode staged share rotation: %w", err)
		}
		if existing.Retire != rotation.Retire || !bytes.Equal(existing.Replacement, rotation.Replacement) {
			return fmt.Errorf("conflicting staged share rotation")
		}
		return nil
	}
	blob, err := json.Marshal(rotation)
	if err != nil {
		return err
	}
	return s.save(pendingKey, blob)
}

// CommitShareRotation promotes the staged rotation onto the active share. The
// committed marker is written after the active-key mutation so a crash before
// it leaves the pending record intact for a safe replay.
func (s *badgerStores) CommitShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) error {
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	pendingKey := keyShareRotationPending(protocolType, keyID, sessionID)
	applyingKey := keyShareRotationApplying(protocolType, keyID, sessionID)
	markerKey := keyShareRotationCommitted(protocolType, keyID, sessionID)

	if marker, err := s.load(markerKey); err != nil {
		return err
	} else if len(marker) > 0 {
		_ = s.delete(pendingKey)
		_ = s.delete(applyingKey)
		return nil
	}
	pendingBlob, err := s.load(pendingKey)
	if err != nil {
		return err
	}
	if len(pendingBlob) == 0 {
		return fmt.Errorf("share rotation is not staged")
	}
	var rotation sdkstorage.ShareRotation
	if err := json.Unmarshal(pendingBlob, &rotation); err != nil {
		return fmt.Errorf("decode staged share rotation: %w", err)
	}
	if err := rotation.Validate(); err != nil {
		return err
	}
	if err := s.save(applyingKey, []byte{1}); err != nil {
		return err
	}
	activeKey := keyShare(protocolType, keyID)
	if rotation.Retire {
		if err := s.delete(activeKey); err != nil {
			return err
		}
	} else if err := s.save(activeKey, rotation.Replacement); err != nil {
		return err
	}
	if err := s.save(markerKey, []byte{1}); err != nil {
		return err
	}
	if err := s.delete(pendingKey); err != nil {
		return err
	}
	return s.delete(applyingKey)
}

// AbortShareRotation drops an un-committed staged rotation, leaving the active
// share untouched. If commit already crossed its durable boundary it is a no-op.
func (s *badgerStores) AbortShareRotation(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) error {
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	pendingKey := keyShareRotationPending(protocolType, keyID, sessionID)
	if marker, err := s.load(keyShareRotationCommitted(protocolType, keyID, sessionID)); err != nil {
		return err
	} else if len(marker) > 0 {
		_ = s.delete(pendingKey)
		_ = s.delete(keyShareRotationApplying(protocolType, keyID, sessionID))
		return nil
	}
	if applying, err := s.load(keyShareRotationApplying(protocolType, keyID, sessionID)); err != nil {
		return err
	} else if len(applying) > 0 {
		// Commit processing already crossed its durable roll-forward boundary.
		return nil
	}
	return s.delete(pendingKey)
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

func (s *badgerStores) LoadSessionCheckpoint(sessionID string) ([]byte, error) {
	return s.load(keyCheckpoint(sessionID))
}

func (s *badgerStores) SaveSessionCheckpoint(sessionID string, checkpoint []byte) error {
	return s.save(keyCheckpoint(sessionID), checkpoint)
}

func (s *badgerStores) DeleteSessionCheckpoint(sessionID string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(keyCheckpoint(sessionID)))
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

func (s *badgerStores) delete(key string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

func keyPreparamsSlot(protocolType sdkprotocol.ProtocolType, slot string) string {
	return fmt.Sprintf("preparams:%s:%s", protocolType, slot)
}

func keyPreparamsActiveSlot(protocolType sdkprotocol.ProtocolType) string {
	return fmt.Sprintf("preparams:%s:active_slot", protocolType)
}

func keyShare(protocolType sdkprotocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("shares:%s:%s", protocolType, keyID)
}

func keyShareMeta(protocolType sdkprotocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("share-meta:%s:%s", protocolType, keyID)
}

func keyShareRotationPending(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) string {
	return fmt.Sprintf("share-rotations:%s:%s:%s:pending", protocolType, keyID, sessionID)
}

func keyShareRotationCommitted(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) string {
	return fmt.Sprintf("share-rotations:%s:%s:%s:committed", protocolType, keyID, sessionID)
}

func keyShareRotationApplying(protocolType sdkprotocol.ProtocolType, keyID, sessionID string) string {
	return fmt.Sprintf("share-rotations:%s:%s:%s:applying", protocolType, keyID, sessionID)
}

func keyArtifact(sessionID string) string {
	return "artifacts:" + sessionID
}

func keyCheckpoint(sessionID string) string {
	return "checkpoint:" + sessionID
}
