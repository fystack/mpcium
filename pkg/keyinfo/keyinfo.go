package keyinfo

import (
	"encoding/json"
	"fmt"

	"github.com/fystack/mpcium/pkg/infra"
)

type KeyInfo struct {
	ParticipantPeerIDs []string `json:"participant_peer_ids"`
	Threshold          int      `json:"threshold"`
	Version            int      `json:"version"`
}

type store struct {
	natsKV infra.NatsKV
}

func NewStore(natsKV infra.NatsKV) *store {
	return &store{natsKV: natsKV}
}

type Store interface {
	Get(walletID string) (*KeyInfo, error)
	Save(walletID string, info *KeyInfo) error
}

func (s *store) Get(walletID string) (*KeyInfo, error) {
	val, err := s.natsKV.Get(s.composeKey(walletID))
	if err != nil {
		return nil, fmt.Errorf("Failed to get key info: %w", err)
	}
	if val == nil {
		return nil, fmt.Errorf("Key info not found")
	}

	info := &KeyInfo{}
	err = json.Unmarshal(val, info)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal key info: %w", err)
	}

	return info, nil
}

func (s *store) Save(walletID string, info *KeyInfo) error {
	bytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal key info: %w", err)
	}

	err = s.natsKV.Put(s.composeKey(walletID), bytes)
	if err != nil {
		return fmt.Errorf("Failed to save key info: %w", err)
	}

	return nil
}

func (s *store) composeKey(walletID string) string {
	return walletID
}
