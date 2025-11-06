package presign

import (
	"context"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/presigninfo"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	MinPoolSize             int
	MaxPoolSize             int
	GlobalMaxConcurrency    int
	PerWalletMaxConcurrency int
	HotWindowDuration       time.Duration
	RefillInterval          time.Duration
}

var DefaultConfig = Config{
	MinPoolSize:             5,
	MaxPoolSize:             20,
	GlobalMaxConcurrency:    20,
	PerWalletMaxConcurrency: 5,
	HotWindowDuration:       5 * time.Minute,
	RefillInterval:          10 * time.Second,
}

type PresignPool struct {
	cfg       *Config
	ctx       context.Context
	cancel    context.CancelFunc
	client    client.MPCClient
	infoStore presigninfo.Store

	wg        sync.WaitGroup
	mu        sync.RWMutex
	hot       map[string]time.Time
	pending   map[string]int
	cache     map[string][]*presigninfo.PresignInfo
	globalSem *semaphore.Weighted
}

func NewPresignPool(cfg *Config, client client.MPCClient, infoStore presigninfo.Store) *PresignPool {
	if cfg == nil {
		tmp := DefaultConfig
		cfg = &tmp
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &PresignPool{
		cfg:       cfg,
		client:    client,
		infoStore: infoStore,
		ctx:       ctx,
		cancel:    cancel,
		hot:       make(map[string]time.Time),
		pending:   make(map[string]int),
		cache:     make(map[string][]*presigninfo.PresignInfo),
		globalSem: semaphore.NewWeighted(int64(cfg.GlobalMaxConcurrency)),
	}

	// Subscribe to presign completion events
	if err := p.client.OnPresignResult(func(evt event.PresignResultEvent) {
		p.OnPresignCompleted(evt.WalletID, evt.TxID, evt.ResultType == event.ResultTypeSuccess)
	}); err != nil {
		logger.Error("subscribe presign handler failed", err)
	}

	return p
}

func (p *PresignPool) Start(ctx context.Context) {
	logger.Info("[PRESIGN] Presign pool worker started")

	p.wg.Add(2)
	go p.refillLoop()
	go p.cleanupLoop()

	go func() {
		<-ctx.Done()
		p.Stop()
	}()
}

func (p *PresignPool) Stop() {
	p.cancel()
	p.wg.Wait()
	logger.Info("presign pool stopped")
}

func (p *PresignPool) TouchHot(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hot[walletID] = time.Now()
	logger.Info("hot wallet detected", "wallet", walletID)
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
			p.syncCache() // refresh cache periodically
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PresignPool) refill() {
	now := time.Now()

	p.mu.RLock()
	wallets := make([]string, 0, len(p.hot))
	for w, t := range p.hot {
		if now.Sub(t) < p.cfg.HotWindowDuration {
			wallets = append(wallets, w)
		}
	}
	p.mu.RUnlock()

	// refill sequentially, with delay between wallets
	for i, wallet := range wallets {
		if i > 0 {
			time.Sleep(2 * time.Second) // spacing between wallets
		}
		if err := p.refillWallet(wallet); err != nil {
			logger.Warn("refill failed", "wallet", wallet, "err", err)
		}
	}
}

func (p *PresignPool) refillWallet(walletID string) error {
	list := p.getPresignListCached(walletID)

	var ready int
	for _, m := range list {
		if m.Status == presigninfo.PresignStatusActive {
			ready++
		}
	}

	if ready >= p.cfg.MinPoolSize {
		return nil
	}

	// Skip if there is a pending request
	p.mu.Lock()
	if p.pending[walletID] > 0 {
		p.mu.Unlock()
		return nil
	}
	p.pending[walletID] = 1
	p.mu.Unlock()

	logger.Info("refilling presign", "wallet", walletID, "current", ready, "target", p.cfg.MinPoolSize)
	go p.requestPresign(walletID)
	return nil
}

func (p *PresignPool) requestPresign(walletID string) {
	if err := p.globalSem.Acquire(p.ctx, 1); err != nil {
		p.decrement(walletID)
		return
	}
	defer p.globalSem.Release(1)

	// throttle lightly to allow other operations to continue
	time.Sleep(3 * time.Second)

	txID := "presign_" + uuid.NewString()
	req := &types.PresignTxMessage{
		KeyType:  types.KeyTypeSecp256k1,
		Protocol: types.ProtocolCGGMP21,
		WalletID: walletID,
		TxID:     txID,
	}

	if err := p.client.PresignTransaction(req); err != nil {
		logger.Error("publish presign failed", err, "wallet", walletID)
		p.decrement(walletID)
		return
	}

	logger.Debug("presign request sent", "wallet", walletID, "tx_id", txID)
}

func (p *PresignPool) OnPresignCompleted(walletID, txID string, success bool) {
	p.decrement(walletID)
	if !success {
		logger.Warn("presign failed", "wallet", walletID, "tx_id", txID)
		return
	}

	info := &presigninfo.PresignInfo{
		TxID:      txID,
		WalletID:  walletID,
		KeyType:   types.KeyTypeSecp256k1,
		Protocol:  types.ProtocolCGGMP21,
		Status:    presigninfo.PresignStatusActive,
		CreatedAt: time.Now(),
	}

	// update cache
	p.mu.Lock()
	p.cache[walletID] = append(p.cache[walletID], info)
	p.mu.Unlock()

	// async write to Consul KV
	go func() {
		if err := p.infoStore.Save(walletID, info); err != nil {
			logger.Error("save presign info failed", err, "wallet", walletID)
		}
	}()
}

func (p *PresignPool) getPresignListCached(walletID string) []*presigninfo.PresignInfo {
	p.mu.RLock()
	cached := p.cache[walletID]
	p.mu.RUnlock()

	if len(cached) > 0 {
		return cached
	}

	// cache miss → load from Consul
	list, err := p.infoStore.ListPendingPresigns(walletID)
	if err != nil {
		logger.Warn("load presign list failed", "wallet", walletID, "err", err)
		return nil
	}

	p.mu.Lock()
	p.cache[walletID] = list
	p.mu.Unlock()
	return list
}

// sync cache periodically
func (p *PresignPool) syncCache() {
	wallets := p.GetHotWalletsSnapshot()
	for _, wallet := range wallets {
		list, err := p.infoStore.ListPendingPresigns(wallet)
		if err != nil {
			logger.Warn("sync cache failed", "wallet", wallet, "err", err)
			continue
		}
		p.mu.Lock()
		p.cache[wallet] = list
		p.mu.Unlock()
	}
}

func (p *PresignPool) decrement(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := p.pending[walletID]; n > 1 {
		p.pending[walletID] = n - 1
	} else {
		delete(p.pending, walletID)
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
