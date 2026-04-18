package coordinator

import (
	"context"
	"sync"
	"time"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type PresenceView interface {
	IsOnline(ctx context.Context, peerID string) bool
	ApplyPresence(event sdkprotocol.PresenceEvent) error
}

type InMemoryPresenceView struct {
	mu    sync.RWMutex
	peers map[string]sdkprotocol.PresenceEvent
}

func NewInMemoryPresenceView() *InMemoryPresenceView {
	return &InMemoryPresenceView{
		peers: make(map[string]sdkprotocol.PresenceEvent),
	}
}

func (p *InMemoryPresenceView) IsOnline(_ context.Context, peerID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	event, ok := p.peers[peerID]
	if !ok {
		return false
	}
	return event.Status == sdkprotocol.PresenceStatusOnline
}

func (p *InMemoryPresenceView) ApplyPresence(event sdkprotocol.PresenceEvent) error {
	if event.PeerID == "" {
		return newCoordinatorError(ErrorCodeValidation, "invalid presence event")
	}
	if event.LastSeenUnixMs <= 0 {
		event.LastSeenUnixMs = time.Now().UTC().UnixMilli()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peers[event.PeerID] = event
	return nil
}
