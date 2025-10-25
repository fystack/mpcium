package taurus

import (
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
)

// PresignCache provides an in-memory cache of pre-signature data
// with automatic TTL-based cleanup.
type PresignCache struct {
	mu   sync.Mutex
	data map[string][]PresignEntry // walletID -> entries
	ttl  time.Duration
}

type PresignEntry struct {
	SessionID string
	Result    *ecdsa.PreSignature
	CreatedAt time.Time
}

// NewPresignCache creates a new cache with optional TTL.
// If ttl <= 0, defaults to 10 minutes.
func NewPresignCache(ttl time.Duration) *PresignCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	cache := &PresignCache{
		data: make(map[string][]PresignEntry),
		ttl:  ttl,
	}

	go cache.startCleanup()
	return cache
}

// Put adds a new presign result for a wallet.
func (c *PresignCache) Put(walletID, sessionID string, res *ecdsa.PreSignature) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[walletID] = append(c.data[walletID], PresignEntry{
		SessionID: sessionID,
		Result:    res,
		CreatedAt: time.Now(),
	})
}

// Get retrieves and removes the oldest available presign for a wallet.
func (c *PresignCache) Get(walletID string) (*ecdsa.PreSignature, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := c.data[walletID]
	if len(entries) == 0 {
		return nil, false
	}

	res := entries[0].Result
	c.data[walletID] = entries[1:] // pop first entry
	if len(c.data[walletID]) == 0 {
		delete(c.data, walletID)
	}
	return res, true
}

// startCleanup periodically removes expired presign entries based on TTL.
func (c *PresignCache) startCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		expireBefore := now.Add(-c.ttl)

		c.mu.Lock()
		for walletID, entries := range c.data {
			filtered := entries[:0]
			for _, e := range entries {
				if e.CreatedAt.After(expireBefore) {
					filtered = append(filtered, e)
				}
			}
			if len(filtered) == 0 {
				delete(c.data, walletID)
			} else {
				c.data[walletID] = filtered
			}
		}
		c.mu.Unlock()
	}
}
