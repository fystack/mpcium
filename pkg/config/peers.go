package config

import (
	"fmt"

	"github.com/fystack/mpcium/pkg/infra"
)

type Peer struct {
	ID   string
	Name string
}

func LoadPeersFromNatsKV(peersKV infra.NatsKV) ([]Peer, error) {
	// Retrieve node IDs from the bucket
	pairs, err := peersKV.List("")
	if err != nil {
		return nil, err
	}

	fmt.Println("List of node IDs in bucket:")
	peers := make([]Peer, 0, len(pairs))
	for key, value := range pairs {
		peers = append(peers, Peer{
			ID:   string(value),
			Name: key,
		})

		fmt.Printf("Key: %s, Value: %s\n", key, string(value))
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
