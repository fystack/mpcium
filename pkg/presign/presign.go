package presign

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	MinPoolSize             int
	MaxPoolSize             int
	HotWindowDuration       time.Duration
	PresignTTL              time.Duration
	GlobalMaxConcurrency    int
	PerWalletMaxConcurrency int
	RefillInterval          time.Duration
}

var DefaultConfig = Config{
	MinPoolSize:             5,                // keep more presigns ready
	MaxPoolSize:             20,               // upper bound (not strictly enforced)
	HotWindowDuration:       5 * time.Minute,  // shorter hot window
	PresignTTL:              10 * time.Minute, // presigns expire sooner
	GlobalMaxConcurrency:    20,               // allow up to 20 concurrent presigns total
	PerWalletMaxConcurrency: 5,                // up to 5 per wallet
	RefillInterval:          10 * time.Second, // check every 5 seconds instead of 30
}

type PresignPool struct {
	cfg       *Config
	client    client.MPCClient
	metaStore *presignMetaStore
	log       *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	peers     []string
	hot       map[string]time.Time
	pending   map[string]int
	globalSem *semaphore.Weighted
}

// NewPresignPool initializes and subscribes to presign responses.
func NewPresignPool(
	client client.MPCClient,
	metaStore *presignMetaStore,
	peers []string,
	log *slog.Logger,
	cfg *Config,
) *PresignPool {
	if cfg == nil {
		tmp := DefaultConfig
		cfg = &tmp
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &PresignPool{
		cfg:       cfg,
		client:    client,
		metaStore: metaStore,
		peers:     peers,
		log:       log,
		ctx:       ctx,
		cancel:    cancel,
		hot:       make(map[string]time.Time),
		pending:   make(map[string]int),
		globalSem: semaphore.NewWeighted(int64(cfg.GlobalMaxConcurrency)),
	}

	// Listen shared presign results
	if err := p.client.OnPresignResult(func(evt event.PresignResultEvent) {
		if evt.ResultType == event.ResultTypeSuccess {
			p.hot[evt.WalletID] = time.Now()
		} else {
			p.log.Error("presign failed", "walletID", evt.WalletID, "error", evt.ErrorReason)
		}
	}); err != nil {
		p.log.Error("subscribe presign handler failed", "err", err)
	}

	return p
}

// Start background workers
func (p *PresignPool) Start(ctx context.Context) {
	p.log.Debug("presign pool started")

	p.wg.Add(2)
	go p.refillLoop()
	go p.cleanupLoop()

	// Initial scan for existing wallets to pre-populate hot list
	go p.initialScan()

	go func() {
		<-ctx.Done()
		p.Stop()
	}()
}

// Stop gracefully
func (p *PresignPool) Stop() {
	p.cancel()
	p.wg.Wait()
	p.log.Info("presign pool stopped")
}

// MarkHot marks a wallet as active
func (p *PresignPool) MarkHot(walletID string) {
	p.mu.Lock()
	p.hot[walletID] = time.Now()
	p.mu.Unlock()
}

// TouchHot refreshes timestamp, or adds if not present
func (p *PresignPool) TouchHot(walletID string) {
	p.mu.Lock()
	p.hot[walletID] = time.Now()
	p.mu.Unlock()
}

func (p *PresignPool) refillLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.RefillInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.refill()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PresignPool) cleanupLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PresignPool) refill() {
	// Skip refill if there are active keygen or sign sessions
	now := time.Now()
	p.mu.RLock()
	wallets := make([]string, 0, len(p.hot))
	for w, t := range p.hot {
		if now.Sub(t) < p.cfg.HotWindowDuration {
			wallets = append(wallets, w)
		}
	}
	p.mu.RUnlock()

	for _, wallet := range wallets {
		if err := p.refillWallet(wallet); err != nil {
			p.log.Warn("refill failed", "wallet", wallet, "err", err)
		}
	}
}

func (p *PresignPool) refillWallet(walletID string) error {
	list, err := p.metaStore.List(walletID)
	if err != nil {
		return fmt.Errorf("list presigns: %w", err)
	}

	var ready int
	if len(list) >= p.cfg.MinPoolSize {
		ready = p.cfg.MinPoolSize
	} else {
		ready = len(list)
	}

	p.log.Debug("refill check", "wallet", walletID, "ready", ready, "min", p.cfg.MinPoolSize)

	p.mu.Lock()
	cur := p.pending[walletID]
	if cur >= p.cfg.PerWalletMaxConcurrency {
		p.mu.Unlock()
		return nil
	}
	need := p.cfg.MinPoolSize - ready
	if need <= 0 {
		p.mu.Unlock()
		return nil
	}
	if need > (p.cfg.PerWalletMaxConcurrency - cur) {
		need = p.cfg.PerWalletMaxConcurrency - cur
	}
	p.pending[walletID] += need
	p.mu.Unlock()

	p.log.Info("refilling presign", "wallet", walletID, "need", need)
	for i := 0; i < need; i++ {
		go p.requestPresign(walletID)
		// add a small random delay between requests
		time.Sleep(time.Duration(150+rand.Intn(150)) * time.Millisecond)
	}
	return nil
}

func (p *PresignPool) requestPresign(walletID string) {
	if err := p.globalSem.Acquire(p.ctx, 1); err != nil {
		p.decrement(walletID)
		return
	}
	defer p.globalSem.Release(1)

	sessionID := "presign_" + uuid.NewString()
	req := &types.PresignTxMessage{
		ID:       uuid.NewString(),
		KeyType:  types.KeyTypeCGGMP21,
		WalletID: walletID,
	}
	if err := p.client.PresignTransaction(req); err != nil {
		p.log.Error("publish presign failed", "wallet", walletID, "err", err)
		p.decrement(walletID)
		return
	}
	p.log.Debug("presign request sent", "wallet", walletID, "session", sessionID)
}

func (p *PresignPool) OnPresignCompleted(walletID, sessionID string, success bool) {
	p.decrement(walletID)
	meta := &PresignMeta{
		SessionID: sessionID,
		WalletID:  walletID,
		Protocol:  "cggmp21",
		CreatedAt: time.Now(),
	}
	if success {
		meta.Status = "active"
		_ = p.metaStore.Save(walletID, sessionID, meta)
	}
}

func (p *PresignPool) decrement(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := p.pending[walletID]; n > 0 {
		n--
		if n == 0 {
			delete(p.pending, walletID)
		} else {
			p.pending[walletID] = n
		}
	}
}
func (p *PresignPool) cleanup() {
	now := time.Now()
	p.mu.Lock()
	for w, t := range p.hot {
		if now.Sub(t) >= p.cfg.HotWindowDuration {
			delete(p.hot, w)
		}
	}
	p.mu.Unlock()

	wallets := p.GetHotWalletsSnapshot()
	for _, w := range wallets {
		ids, _ := p.metaStore.List(w)
		for _, id := range ids {
			m, err := p.metaStore.Get(w, id)
			if err != nil || m == nil {
				continue
			}
			exp := m.CreatedAt.Add(p.cfg.PresignTTL)
			if now.After(exp) || m.Status == "used" {
				_ = p.metaStore.Delete(w, id)
			}
		}
	}
}

func (p *PresignPool) GetHotWalletsSnapshot() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	keys := make([]string, 0, len(p.hot))
	for k := range p.hot {
		keys = append(keys, k)
	}
	return keys
}

// initialScan discovers existing presign wallets and marks them as hot
func (p *PresignPool) initialScan() {
	// List all existing presign metadata to discover active wallets
	// This is a best-effort scan to bootstrap the pool
	wallets := p.discoverWallets()

	p.mu.Lock()
	for _, wallet := range wallets {
		if _, exists := p.hot[wallet]; !exists {
			p.hot[wallet] = time.Now()
			p.log.Info("discovered wallet, marking as hot", "wallet", wallet)
		}
	}
	p.mu.Unlock()

	p.log.Info("presign pool: initial scan completed", "wallets", len(wallets))
}

// discoverWallets attempts to find wallets with existing presign metadata
func (p *PresignPool) discoverWallets() []string {
	// We don't have direct access to list all wallets from the meta store
	// This is a limitation - the meta store doesn't provide a ListAllWallets method
	// For now, return empty list - wallets will be discovered as they're used
	// TODO: Add a method to scan the storage for all known wallets
	return []string{}
}
