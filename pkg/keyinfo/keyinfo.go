package keyinfo

import (
	"encoding/json"
	"fmt"

	"github.com/fystack/mpcium/pkg/infra"
	"github.com/hashicorp/consul/api"
)

type KeyInfo struct {
	ParticipantPeerIDs []string `json:"participant_peer_ids"`
	Threshold          int      `json:"threshold"`
	Version            int      `json:"version"`
}

type store struct {
	consulKV infra.ConsulKV
}

func NewStore(consulKV infra.ConsulKV) *store {
	return &store{consulKV: consulKV}
}

type Store interface {
	Get(walletID string) (*KeyInfo, error)
	Save(walletID string, info *KeyInfo) error
}

func (s *store) Get(walletID string) (*KeyInfo, error) {
	pair, _, err := s.consulKV.Get(s.composeKey(walletID), nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to get key info: %w", err)
	}
	if pair == nil {
		return nil, fmt.Errorf("Key info not found")
	}

	info := &KeyInfo{}
	err = json.Unmarshal(pair.Value, info)
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

	pair := &api.KVPair{
		Key:   s.composeKey(walletID),
		Value: bytes,
	}

	_, err = s.consulKV.Put(pair, nil)
	if err != nil {
		return fmt.Errorf("Failed to save key info: %w", err)
	}

	return nil
}

func (s *store) composeKey(walletID string) string {
	return fmt.Sprintf("threshold_keyinfo/%s", walletID)
}
