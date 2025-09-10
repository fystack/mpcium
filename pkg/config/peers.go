package config

import (
	"fmt"

	"github.com/fystack/mpcium/pkg/logger"
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
	debugPeers, _, err := kv.List("mpc_peers", nil)
	if err != nil {
		return nil, err
	}
	logger.Info("Loaded peers from consul prefix", "preifx", prefix)
	logger.Info("Loaded peers from consul", "pairs", pairs)
	logger.Info("Loaded peers from consul", "peers2", debugPeers)

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

func GetNodeID(nodeName string, peers []Peer) string {
	for _, peer := range peers {
		if peer.Name == nodeName {
			return peer.ID
		}
	}

	return ""
}
