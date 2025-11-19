package presigninfo

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/hashicorp/consul/api"
)

const (
	PresignStatusActive = "active"
	PresignStatusUsed   = "used"
)

type PresignInfo struct {
	TxID      string         `json:"tx_id"`
	WalletID  string         `json:"wallet_id"`
	KeyType   types.KeyType  `json:"key_type"`
	Protocol  types.Protocol `json:"protocol"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	UsedAt    *time.Time     `json:"used_at,omitempty"`
}

type store struct {
	consulKV infra.ConsulKV
}

func NewStore(consulKV infra.ConsulKV) *store {
	return &store{consulKV: consulKV}
}

type Store interface {
	Get(walletID string, txID string) (*PresignInfo, error)
	Save(walletID string, info *PresignInfo) error
	Delete(walletID string, txID string) error
	ListPendingPresigns(walletID string) ([]*PresignInfo, error)
	ListAllWallets() ([]string, error)
}

func (s *store) Get(walletID string, txID string) (*PresignInfo, error) {
	pair, _, err := s.consulKV.Get(s.composeKey(walletID, txID), nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to get presign info: %w", err)
	}
	if pair == nil {
		return nil, fmt.Errorf("Presign info not found")
	}

	info := &PresignInfo{}
	err = json.Unmarshal(pair.Value, info)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal presign info: %w", err)
	}

	return info, nil
}

func (s *store) Save(walletID string, info *PresignInfo) error {
	bytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal presign info: %w", err)
	}

	pair := &api.KVPair{
		Key:   s.composeKey(walletID, info.TxID),
		Value: bytes,
	}

	_, err = s.consulKV.Put(pair, nil)
	if err != nil {
		return fmt.Errorf("Failed to save presign info: %w", err)
	}

	return nil
}

func (s *store) Delete(walletID string, txID string) error {
	_, err := s.consulKV.Delete(s.composeKey(walletID, txID), nil)
	if err != nil {
		return fmt.Errorf("Failed to delete presign info: %w", err)
	}
	return nil
}

// ListPendingPresigns returns all pending presigns for a given wallet ID
func (s *store) ListPendingPresigns(walletID string) ([]*PresignInfo, error) {
	entries, _, err := s.consulKV.List(s.composeKey(walletID, ""), nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to list presign info: %w", err)
	}
	infos := make([]*PresignInfo, 0, len(entries))
	for _, entry := range entries {
		info := &PresignInfo{}
		if err := json.Unmarshal(entry.Value, info); err != nil {
			return nil, fmt.Errorf("Failed to unmarshal presign info: %w", err)
		}
		if info.TxID != "" {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

// ListAllWallets returns all wallet IDs that have presigns in Consul KV
func (s *store) ListAllWallets() ([]string, error) {
	entries, _, err := s.consulKV.List("presign_info/", nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all presign info: %w", err)
	}

	walletMap := make(map[string]bool)
	for _, entry := range entries {
		// Key format: presign_info/{walletID}/{txID}
		// Extract walletID from the key
		key := entry.Key
		parts := strings.Split(key, "/")
		if len(parts) >= 2 && parts[0] == "presign_info" {
			walletID := parts[1]
			if walletID != "" {
				walletMap[walletID] = true
			}
		}
	}

	wallets := make([]string, 0, len(walletMap))
	for walletID := range walletMap {
		wallets = append(wallets, walletID)
	}
	return wallets, nil
}

func (s *store) composeKey(walletID string, txID string) string {
	return fmt.Sprintf("presign_info/%s/%s", walletID, txID)
}
