package mpc

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/hashicorp/consul/api"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

const (
	ReadinessCheckPeriod = 1 * time.Second
)

type PeerRegistry interface {
	Ready() error
	ArePeersReady() bool
	AreMajorityReady() bool
	WatchPeersReady()
	// Resign is called by the node when it is going to shutdown
	Resign() error
	GetReadyPeersCount() int64
	GetReadyPeersCountExcludeSelf() int64
	GetReadyPeersIncludeSelf() []string // get ready peers include self
	GetTotalPeersCount() int64

	OnPeerConnected(callback func(peerID string))
	OnPeerDisconnected(callback func(peerID string))
	OnPeerReConnected(callback func(peerID string))
}

type registry struct {
	nodeID      string
	peerNodeIDs []string
	readyMap    map[string]bool
	readyCount  int64
	mu          sync.RWMutex
	ready       bool // ready is true when all peers are ready

	consulKV      infra.ConsulKV
	healthCheck   messaging.DirectMessaging
	pubSub        messaging.PubSub
	identityStore identity.Store
	ecdhSession   ECDHSession
	mpcThreshold  int

	onPeerConnected    func(peerID string)
	onPeerDisconnected func(peerID string)
	onPeerReConnected  func(peerID string)
}

func NewRegistry(
	nodeID string,
	peerNodeIDs []string,
	consulKV infra.ConsulKV,
	directMessaging messaging.DirectMessaging,
	pubSub messaging.PubSub,
	identityStore identity.Store,
) *registry {
	ecdhSession := NewECDHSession(nodeID, peerNodeIDs, pubSub, identityStore)
	mpcThreshold := viper.GetInt("mpc_threshold")
	if mpcThreshold < 1 {
		logger.Fatal("mpc_threshold must be greater than 0", nil)
	}

	return &registry{
		consulKV:      consulKV,
		nodeID:        nodeID,
		peerNodeIDs:   getPeerIDsExceptSelf(nodeID, peerNodeIDs),
		readyMap:      make(map[string]bool),
		readyCount:    1, // self
		healthCheck:   directMessaging,
		pubSub:        pubSub,
		identityStore: identityStore,
		ecdhSession:   ecdhSession,
		mpcThreshold:  mpcThreshold,
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

func (r *registry) readyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (r *registry) registerReadyPairs(peerIDs []string) {
	for _, peerID := range peerIDs {
		ready, exist := r.readyMap[peerID]
		if !exist {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Register", "peerID", peerID)
			if r.onPeerConnected != nil {
				r.onPeerConnected(peerID)
			}
			go r.triggerECDHExchange()
		} else if !ready {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Reconnecting...", "peerID", peerID)
			if r.onPeerReConnected != nil {
				r.onPeerReConnected(peerID)
			}
			go r.triggerECDHExchange()
		}

		r.readyMap[peerID] = true
	}

	if len(peerIDs) == len(r.peerNodeIDs) && !r.ready {
		r.mu.Lock()
		r.ready = true
		r.mu.Unlock()
		logger.Info("All peers are ready including ECDH exchange completion")
	}
}

// triggerECDHExchange safely triggers ECDH key exchange
func (r *registry) triggerECDHExchange() {
	logger.Info("Triggering ECDH key exchange")
	if err := r.ecdhSession.BroadcastPublicKey(); err != nil {
		logger.Error("Failed to trigger ECDH exchange", err)
	}
}

// Ready is called by the node when it complete generate preparams and starting to accept
// incoming requests
func (r *registry) Ready() error {
	// Start ECDH exchange first
	if err := r.startECDHExchange(); err != nil {
		return fmt.Errorf("failed to start ECDH exchange: %w", err)
	}

	k := r.readyKey(r.nodeID)

	kv := &api.KVPair{
		Key:   k,
		Value: []byte("true"),
	}

	_, err := r.consulKV.Put(kv, nil)
	if err != nil {
		return fmt.Errorf("Put ready key failed: %w", err)
	}

	_, err = r.healthCheck.Listen(r.composeHealthCheckTopic(r.nodeID), func(data []byte) {
		peerID, ecdhReadyPeersCount, _ := parseHealthDataSplit(string(data))
		logger.Debug("Health check ok", "peerID", peerID)
		if ecdhReadyPeersCount < int(r.GetReadyPeersCountExcludeSelf()) {
			logger.Info("[ECDH exchange retriggerd] not all peers are ready", "peerID", peerID)
			go r.triggerECDHExchange()

		}
	})
	if err != nil {
		return fmt.Errorf("Listen health check failed: %w", err)
	}
	return nil
}

func (r *registry) WatchPeersReady() {
	go r.checkPeersHealth()

	ticker := time.NewTicker(ReadinessCheckPeriod)
	// first tick is executed immediately
	for ; true; <-ticker.C {
		pairs, _, err := r.consulKV.List("ready/", nil)
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

					// Remove ECDH key for disconnected peer
					r.ecdhSession.RemovePeer(peerID)

					if r.onPeerDisconnected != nil {
						r.onPeerDisconnected(peerID)
					}
				}

			}

		}
		r.registerReadyPairs(newReadyPeerIDs)
	}

}

func (r *registry) checkPeersHealth() {
	for {
		time.Sleep(5 * time.Second)
		if !r.ArePeersReady() {
			logger.Info("Peers are not ready yet", "ready", r.GetReadyPeersCount(), "expected", len(r.peerNodeIDs)+1)
		}

		pairs, _, err := r.consulKV.List("ready/", nil)
		if err != nil {
			logger.Error("List ready keys failed", err)
			continue
		}
		readyPeerIDs := r.getReadyPeersFromKVStore(pairs)
		for _, peerID := range readyPeerIDs {
			err := r.healthCheck.SendToOtherWithRetry(r.composeHealthCheckTopic(peerID), []byte(r.composeHealthData()), messaging.RetryConfig{
				RetryAttempt: 2,
			})
			if err != nil && strings.Contains(err.Error(), "no responders") {
				logger.Info("No response from peer", "peerID", peerID)
				_, err := r.consulKV.Delete(r.readyKey(peerID), nil)
				if err != nil {
					logger.Error("Delete ready key failed", err)
				}
			}
		}
	}
}

// GetReadyPeersCount returns the number of ready peers including self
// should -1 if want to exclude self
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
		_, err := fmt.Sscanf(k.Key, "ready/%s", &peerNodeID)
		if err != nil {
			logger.Error("Parse ready key failed", err)
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

	// Check both peer connectivity and ECDH completion
	return r.ready && r.isECDHReady()
}

// AreMajorityReady checks if a majority of peers are ready.
// Returns true only if:
//  1. The number of ready peers (including self) is greater than mpcThreshold+1
//  2. Symmetric keys are fully established among all ready peers (excluding self).
func (r *registry) AreMajorityReady() bool {
	readyCount := r.GetReadyPeersCount()
	return int(readyCount) >= r.mpcThreshold+1 && r.isECDHReady()
}

func (r *registry) GetTotalPeersCount() int64 {
	var self int64 = 1
	return int64(len(r.peerNodeIDs)) + self
}

func (r *registry) Resign() error {
	k := r.readyKey(r.nodeID)

	_, err := r.consulKV.Delete(k, nil)
	if err != nil {
		return fmt.Errorf("Delete ready key failed: %w", err)
	}

	return nil
}

func (r *registry) OnPeerConnected(callback func(peerID string)) {
	r.onPeerConnected = callback
}

func (r *registry) OnPeerDisconnected(callback func(peerID string)) {
	r.onPeerDisconnected = callback
}

func (r *registry) OnPeerReConnected(callback func(peerID string)) {
	r.onPeerReConnected = callback
}

// StartECDHExchange starts the ECDH key exchange process
func (r *registry) startECDHExchange() error {
	if err := r.ecdhSession.ListenKeyExchange(); err != nil {
		return fmt.Errorf("failed to start ECDH listener: %w", err)
	}

	if err := r.ecdhSession.BroadcastPublicKey(); err != nil {
		return fmt.Errorf("failed to broadcast ECDH public key: %w", err)
	}

	return nil
}

func (r *registry) GetReadyPeersCountExcludeSelf() int64 {
	return r.GetReadyPeersCount() - 1
}

func (r *registry) isECDHReady() bool {
	requiredKeyCount := r.GetReadyPeersCountExcludeSelf()
	return r.identityStore.CheckSymmetricKeyComplete(int(requiredKeyCount))
}

func (r *registry) composeHealthCheckTopic(nodeID string) string {
	return fmt.Sprintf("healthcheck:%s", nodeID)
}

func (r *registry) composeHealthData() string {
	return fmt.Sprintf("%s,%d", r.nodeID, r.ecdhSession.GetReadyPeersCount())
}

func parseHealthDataSplit(s string) (peerID string, readyCount int, err error) {
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format: %q", s)
	}

	peerID = parts[0]
	readyCount, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, err
	}
	return peerID, readyCount, nil

}
