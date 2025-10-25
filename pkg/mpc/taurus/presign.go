package taurus

import (
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
)

type PresignCache struct {
	mu   sync.Mutex
	data map[string][]PresignEntry // walletID -> entries
}

type PresignEntry struct {
	SessionID string
	Result    *ecdsa.PreSignature
	CreatedAt time.Time
}

func NewPresignCache() *PresignCache {
	return &PresignCache{
		data: make(map[string][]PresignEntry),
	}
}

func (c *PresignCache) Put(walletID, sessionID string, res *ecdsa.PreSignature) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[walletID] = append(c.data[walletID], PresignEntry{
		SessionID: sessionID,
		Result:    res,
		CreatedAt: time.Now(),
	})
}

func (c *PresignCache) Get(walletID string) (*ecdsa.PreSignature, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := c.data[walletID]
	if len(entries) == 0 {
		return nil, false
	}
	res := entries[0].Result
	c.data[walletID] = entries[1:]
	return res, true
}
