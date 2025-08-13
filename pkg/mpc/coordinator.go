package mpc

import (
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
)

// ReshareCoordinator handles coordination between nodes during resharing
type ReshareCoordinator struct {
	kv        *api.KV
	prefix    string
	nodeID    string
	readyPath string
}

// NewReshareCoordinator creates a new coordinator for resharing
func NewReshareCoordinator(consulClient *api.Client, walletID string, nodeID string) *ReshareCoordinator {
	prefix := fmt.Sprintf("reshare/%s", walletID)
	readyPath := fmt.Sprintf("%s/ready/%s", prefix, nodeID)

	return &ReshareCoordinator{
		kv:        consulClient.KV(),
		prefix:    prefix,
		nodeID:    nodeID,
		readyPath: readyPath,
	}
}

// SignalReady marks this node as ready for resharing
func (c *ReshareCoordinator) SignalReady() error {
	p := &api.KVPair{
		Key:   c.readyPath,
		Value: []byte("ready"),
	}

	_, err := c.kv.Put(p, nil)
	if err != nil {
		return fmt.Errorf("failed to signal ready: %w", err)
	}

	logger.Info("Node signaled ready for resharing", "nodeID", c.nodeID)
	return nil
}

// WaitForAll waits until all participants are ready
func (c *ReshareCoordinator) WaitForAll(participants []string) error {
	deadline := time.Now().Add(30 * time.Second)

	for {
		allReady := true
		for _, p := range participants {
			readyPath := fmt.Sprintf("%s/ready/%s", c.prefix, p)
			pair, _, err := c.kv.Get(readyPath, nil)
			if err != nil {
				return fmt.Errorf("failed to check ready state: %w", err)
			}
			if pair == nil {
				allReady = false
				break
			}
		}

		if allReady {
			logger.Info("All participants ready for resharing",
				"nodeID", c.nodeID,
				"participants", participants)
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for participants")
		}

		time.Sleep(1 * time.Second)
	}
}

// Cleanup removes coordination data
func (c *ReshareCoordinator) Cleanup() error {
	_, err := c.kv.DeleteTree(c.prefix, nil)
	if err != nil {
		return fmt.Errorf("failed to cleanup coordination data: %w", err)
	}
	return nil
}
