package presign

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fystack/mpcium/pkg/infra"
	"github.com/hashicorp/consul/api"
)

// PresignMeta represents metadata about a pre-sign session.
type PresignMeta struct {
	SessionID string    `json:"session_id"`
	WalletID  string    `json:"wallet_id"`
	Protocol  string    `json:"protocol"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type presignMetaStore struct {
	consulKV infra.ConsulKV
}

func NewPresignMetaStore(consulKV infra.ConsulKV) *presignMetaStore {
	return &presignMetaStore{consulKV: consulKV}
}

type Store interface {
	Get(walletID string) (*PresignMeta, error)
	Save(walletID string) (*PresignMeta, error)
}

func (s *presignMetaStore) Get(walletID string, sessionID string) (*PresignMeta, error) {
	pair, _, err := s.consulKV.Get(s.composeKey(walletID, sessionID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get presign meta: %w", err)
	}
	if pair == nil {
		return nil, fmt.Errorf("presign meta not found")
	}
	meta := &PresignMeta{}
	err = json.Unmarshal(pair.Value, meta)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal presign meta: %w", err)
	}
	return meta, nil
}

func (s *presignMetaStore) Save(walletID string, sessionID string, info *PresignMeta) error {
	bytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal presign meta: %w", err)
	}
	pair := &api.KVPair{
		Key:   s.composeKey(walletID, sessionID),
		Value: bytes,
	}

	_, err = s.consulKV.Put(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to save presign meta: %w", err)
	}
	return nil
}

func (s *presignMetaStore) List(walletID string) ([]string, error) {
	pairs, _, err := s.consulKV.List(s.composeKey(walletID, ""), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list presign meta: %w", err)
	}
	if pairs == nil {
		return nil, fmt.Errorf("presign meta not found")
	}
	ids := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		// Key format: presign_meta/<walletID>/<sessionID>
		parts := strings.Split(kv.Key, "/")
		if len(parts) > 0 {
			ids = append(ids, parts[len(parts)-1])
		}
	}
	return ids, nil
}

func (s *presignMetaStore) composeKey(walletID string, sessionID string) string {
	return fmt.Sprintf("presign_meta/%s/%s", walletID, sessionID)
}

func (s *presignMetaStore) Delete(walletID string, sessionID string) error {
	_, err := s.consulKV.Delete(s.composeKey(walletID, sessionID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete presign meta: %w", err)
	}
	return nil
}
