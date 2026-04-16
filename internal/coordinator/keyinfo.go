package coordinator

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type KeyInfo struct {
	WalletID     string   `json:"wallet_id"`
	KeyType      string   `json:"key_type,omitempty"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	PublicKey    []byte   `json:"public_key,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

type MemoryKeyInfoStore struct {
	mu    sync.RWMutex
	infos map[string]KeyInfo
}

func NewMemoryKeyInfoStore() *MemoryKeyInfoStore {
	return &MemoryKeyInfoStore{infos: make(map[string]KeyInfo)}
}

func (s *MemoryKeyInfoStore) Save(info KeyInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info.CreatedAt == "" {
		info.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	s.infos[info.WalletID] = info
}

func (s *MemoryKeyInfoStore) Get(walletID string) (KeyInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.infos[walletID]
	return info, ok
}

func RestoreKeyInfoFromSnapshotStore(ctx context.Context, snapshots SnapshotStore, store *MemoryKeyInfoStore) error {
	if snapshots == nil || store == nil {
		return nil
	}
	infos, err := snapshots.LoadKeyInfos(ctx)
	if err != nil {
		return fmt.Errorf("load key info snapshots: %w", err)
	}
	for _, info := range infos {
		store.Save(info)
	}
	return nil
}
