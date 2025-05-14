package mpc

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
	"github.com/samber/lo"
)

const (
	ReadinessCheckPeriod = 1 * time.Second
)

type PeerRegistry interface {
	Ready() error
	ArePeersReady() bool
	WatchPeersReady()
	// Resign is called by the node when it is going to shutdown
	Resign() error
	GetReadyPeersCount() int64
	GetReadyPeersIncludeSelf() []string // get ready peers include self
}

type registry struct {
	clusterID   string
	nodeID      string
	peerNodeIDs []string
	readyMap    map[string]bool
	readyCount  int64
	mu          sync.RWMutex
	ready       bool // ready is true when all peers are ready

	consulKV infra.ConsulKV
}

func NewRegistry(
	clusterID string,
	nodeID string,
	peerNodeIDs []string,
	consulKV infra.ConsulKV,
) *registry {
	return &registry{
		clusterID:   clusterID,
		consulKV:    consulKV,
		nodeID:      nodeID,
		peerNodeIDs: getPeerIDsExceptSelf(nodeID, peerNodeIDs),
		readyMap:    make(map[string]bool),
		readyCount:  1, // self
	}
}

func getPeerIDsExceptSelf(nodeID string, peerNodeIDs []string) []string {
	peerIDs := make([]string, 0, len(peerNodeIDs))
	for _, peerID := range peerNodeIDs {
		if peerID != nodeID {
			peerIDs = append(peerIDs, peerID)
		}
	}
	return peerIDs
}

func (r *registry) readyKey(clusterID string, nodeID string) string {
	return fmt.Sprintf("ready/%s/%s", clusterID, nodeID)
}

func (r *registry) registerReadyPairs(peerIDs []string) {
	for _, peerID := range peerIDs {
		ready, exist := r.readyMap[peerID]
		if !exist {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Register", "peerID", peerID)
		} else if !ready {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Reconnecting...", "peerID", peerID)
		}

		r.readyMap[peerID] = true
	}

	if len(peerIDs) == len(r.peerNodeIDs) && !r.ready {
		r.mu.Lock()
		r.ready = true
		r.mu.Unlock()
		logger.Info("ALL PEERS ARE READY! Starting to accept MPC requests")
	}

}

// Ready is called by the node when it complete generate preparams and starting to accept
// incoming requests
func (r *registry) Ready() error {
	k := r.readyKey(r.clusterID, r.nodeID)

	kv := &api.KVPair{
		Key:   k,
		Value: []byte("true"),
	}

	_, err := r.consulKV.Put(kv, nil)
	if err != nil {
		return fmt.Errorf("Put ready key failed: %w", err)
	}

	return nil
}

func (r *registry) WatchPeersReady() {
	ticker := time.NewTicker(ReadinessCheckPeriod)
	go r.logReadyStatus()
	// first tick is executed immediately
	for ; true; <-ticker.C {
		pairs, _, err := r.consulKV.List(fmt.Sprintf("ready/%s/", r.clusterID), nil)
		if err != nil {
			logger.Error("List ready keys failed", err)
		}

		newReadyPeerIDs := r.getReadyPeersFromKVStore(pairs)
		if len(newReadyPeerIDs) != len(r.peerNodeIDs) {
			r.mu.Lock()
			r.ready = false
			r.mu.Unlock()

			var readyPeerIDs []string
			for peerID, isReady := range r.readyMap {
				if isReady {
					readyPeerIDs = append(readyPeerIDs, peerID)
				}
			}

			disconnecteds, _ := lo.Difference(readyPeerIDs, newReadyPeerIDs)
			if len(disconnecteds) > 0 {
				for _, peerID := range disconnecteds {
					logger.Warn("Peer disconnected!", "peerID", peerID)
					r.readyMap[peerID] = false
					atomic.AddInt64(&r.readyCount, -1)
				}

			}

		}
		r.registerReadyPairs(newReadyPeerIDs)
	}

}

func (r *registry) logReadyStatus() {
	for {
		time.Sleep(5 * time.Second)
		if !r.ArePeersReady() {
			logger.Info("Peers are not ready yet", "ready", r.GetReadyPeersCount(), "expected", len(r.peerNodeIDs)+1)
		}
	}
}

func (r *registry) GetReadyPeersCount() int64 {
	return atomic.LoadInt64(&r.readyCount)
}

func (r *registry) GetReadyPeersIncludeSelf() []string {
	var peerIDs []string
	for peerID, isReady := range r.readyMap {
		if isReady {
			peerIDs = append(peerIDs, peerID)
		}
	}

	peerIDs = append(peerIDs, r.nodeID) // append self
	return peerIDs
}

func (r *registry) getReadyPeersFromKVStore(kvPairs api.KVPairs) []string {
	var peers []string
	for _, k := range kvPairs {
		var peerNodeID string
		parts := strings.Split(k.Key, "/")
		if len(parts) == 3 && parts[0] == "ready" {
			peerNodeID = parts[2]
		}
		if peerNodeID == r.nodeID {
			continue
		}

		peers = append(peers, peerNodeID)
	}

	return peers
}

func (r *registry) ArePeersReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.ready
}

func (r *registry) Resign() error {
	k := r.readyKey(r.clusterID, r.nodeID)

	_, err := r.consulKV.Delete(k, nil)
	if err != nil {
		return fmt.Errorf("Delete ready key failed: %w", err)
	}

	return nil
}
