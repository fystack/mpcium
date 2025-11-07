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
	MinPoolSize          int
	MaxPoolSize          int
	GlobalMaxConcurrency int
	HotWindowDuration    time.Duration
	RefillInterval       time.Duration
	ThrottleDelay        time.Duration
}

var DefaultConfig = Config{
	MinPoolSize:          5,
	MaxPoolSize:          20,
	GlobalMaxConcurrency: 10,
	HotWindowDuration:    5 * time.Minute,
	RefillInterval:       15 * time.Second,
	ThrottleDelay:        5 * time.Second,
}

type walletState struct {
	lastTouch    time.Time
	pendingCount int
}

type PresignPool struct {
	cfg       *Config
	ctx       context.Context
	cancel    context.CancelFunc
	client    client.MPCClient
	infoStore presigninfo.Store

	wg        sync.WaitGroup
	mu        sync.RWMutex
	wallets   map[string]*walletState
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
		wallets:   make(map[string]*walletState),
		globalSem: semaphore.NewWeighted(int64(cfg.GlobalMaxConcurrency)),
	}

	// Subscribe to presign completion
	if err := p.client.OnPresignResult(func(evt event.PresignResultEvent) {
		p.handlePresignResult(evt.WalletID, evt.TxID, evt.ResultType == event.ResultTypeSuccess)
	}); err != nil {
		logger.Error("[PRESIGN] subscribe handler failed", err)
	}
	return p
}

func (p *PresignPool) Start(ctx context.Context) {
	logger.Info("[PRESIGN] Pool started")
	p.wg.Add(1)
	go p.mainLoop()
	go func() {
		<-ctx.Done()
		p.Stop()
	}()
}

func (p *PresignPool) Stop() {
	p.cancel()
	p.wg.Wait()
	logger.Info("[PRESIGN] Pool stopped")
}

func (p *PresignPool) TouchHot(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if state, ok := p.wallets[walletID]; ok {
		state.lastTouch = time.Now()
	} else {
		p.wallets[walletID] = &walletState{lastTouch: time.Now()}
	}
}

func (p *PresignPool) mainLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.RefillInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.refillAll()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PresignPool) refillAll() {
	for _, walletID := range p.getHotWallets() {
		select {
		case <-p.ctx.Done():
			return
		default:
			p.refillWallet(walletID)
			time.Sleep(2 * time.Second)
		}
	}
}

func (p *PresignPool) refillWallet(walletID string) {
	list, err := p.infoStore.ListPendingPresigns(walletID)
	if err != nil {
		logger.Warn("[PRESIGN] list presigns failed", "wallet", walletID, "err", err)
		return
	}

	activeCount := 0
	for _, info := range list {
		if info.Status == presigninfo.PresignStatusActive {
			activeCount++
		}
	}

	p.mu.RLock()
	pendingCount := 0
	if st := p.wallets[walletID]; st != nil {
		pendingCount = st.pendingCount
	}
	p.mu.RUnlock()

	total := activeCount + pendingCount
	if total >= p.cfg.MinPoolSize {
		return
	}
	if pendingCount > 0 {
		return
	}

	p.incrementPending(walletID)
	go p.requestPresign(walletID)
}

func (p *PresignPool) requestPresign(walletID string) {
	if err := p.globalSem.Acquire(p.ctx, 1); err != nil {
		logger.Warn("[PRESIGN] semaphore acquire failed", "wallet", walletID, "err", err)
		p.decrementPending(walletID)
		return
	}
	defer p.globalSem.Release(1)

	time.Sleep(p.cfg.ThrottleDelay)

	txID := "presign_" + uuid.NewString()
	req := &types.PresignTxMessage{
		KeyType:  types.KeyTypeSecp256k1,
		Protocol: types.ProtocolCGGMP21,
		WalletID: walletID,
		TxID:     txID,
	}
	if err := p.client.PresignTransaction(req); err != nil {
		logger.Warn("[PRESIGN] presign publish failed", "wallet", walletID, "tx", txID, "err", err)
		p.decrementPending(walletID)
		return
	}
	logger.Debug("[PRESIGN] presign sent", "wallet", walletID, "tx", txID)
}

func (p *PresignPool) handlePresignResult(walletID, txID string, success bool) {
	p.decrementPending(walletID)

	if !success {
		logger.Warn("[PRESIGN] presign failed", "wallet", walletID, "tx", txID)
		_ = p.infoStore.Delete(walletID, txID) // cleanup failed presign
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
	if err := p.infoStore.Save(walletID, info); err != nil {
		logger.Warn("[PRESIGN] save failed", "wallet", walletID, "tx", txID, "err", err)
		return
	}

	// Clean up expired/used presigns
	p.cleanupUsed(walletID)
	logger.Debug("[PRESIGN] presign done", "wallet", walletID, "tx", txID)
}

func (p *PresignPool) cleanupUsed(walletID string) {
	list, err := p.infoStore.ListPendingPresigns(walletID)
	if err != nil {
		return
	}
	for _, inf := range list {
		if inf.Status == presigninfo.PresignStatusUsed {
			_ = p.infoStore.Delete(walletID, inf.TxID)
			logger.Debug("[PRESIGN] cleaned used presign", "wallet", walletID, "tx", inf.TxID)
		}
	}
}

func (p *PresignPool) getHotWallets() []string {
	now := time.Now()
	p.mu.RLock()
	defer p.mu.RUnlock()
	hot := make([]string, 0, len(p.wallets))
	for id, st := range p.wallets {
		if now.Sub(st.lastTouch) < p.cfg.HotWindowDuration {
			hot = append(hot, id)
		}
	}
	return hot
}

func (p *PresignPool) incrementPending(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.wallets[walletID]; ok {
		st.pendingCount++
	} else {
		p.wallets[walletID] = &walletState{lastTouch: time.Now(), pendingCount: 1}
	}
}

func (p *PresignPool) decrementPending(walletID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.wallets[walletID]; ok && st.pendingCount > 0 {
		st.pendingCount--
	}
}

func (p *PresignPool) GetHotWalletsSnapshot() []string { return p.getHotWallets() }
