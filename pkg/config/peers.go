package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/consul/api"
)

type Peer struct {
	ID   string
	Name string
}

func LoadPeersFromConsul(kv *api.KV, prefix string) ([]Peer, error) {
	// Retrieve node IDs with the "peers" prefix
	pairs, _, err := kv.List(prefix, nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("List of node IDs with the prefix: " + prefix)
	peers := make([]Peer, 0, len(pairs))
	for _, pair := range pairs {
		peers = append(peers, Peer{
			ID: string(pair.Value),
			// remove prefix from key
			Name: pair.Key[len(prefix):],
		})

		fmt.Printf("Key: %s, Value: %s\n", pair.Key, pair.Value)
	}

	return peers, nil
}

// LoadPeersFromFile loads peers from a JSON file (map[string]string: name -> ID)
func LoadPeersFromFile(path string) ([]Peer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read peers file: %w", err)
	}

	var peersMap map[string]string
	if err := json.Unmarshal(data, &peersMap); err != nil {
		return nil, fmt.Errorf("failed to parse peers JSON: %w", err)
	}

	if len(peersMap) == 0 {
		return nil, fmt.Errorf("no peers found in file %s", path)
	}

	peers := make([]Peer, 0, len(peersMap))
	for name, id := range peersMap {
		peers = append(peers, Peer{
			ID:   id,
			Name: name,
		})
	}

	return peers, nil
}

const PeersPrefix = "mpc_peers/"

// SyncPeersToConsul registers new peers from a file into Consul.
// Existing peers are skipped. New peers are registered and logged.
func SyncPeersToConsul(kv *api.KV, peers []Peer) error {
	for _, peer := range peers {
		key := PeersPrefix + peer.Name

		existing, _, err := kv.Get(key, nil)
		if err != nil {
			return fmt.Errorf("failed to check existing key %s: %w", key, err)
		}

		if existing != nil {
			continue
		}

		p := &api.KVPair{Key: key, Value: []byte(peer.ID)}
		if _, err := kv.Put(p, nil); err != nil {
			return fmt.Errorf("failed to register peer %s in Consul: %w", peer.Name, err)
		}
		fmt.Printf("New peer registered: %s with ID %s\n", peer.Name, peer.ID)
	}

	return nil
}

func GetNodeID(nodeName string, peers []Peer) string {
	for _, peer := range peers {
		if peer.Name == nodeName {
			return peer.ID
		}
	}

	return ""
}
