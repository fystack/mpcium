package taurus

import (
	"sync"

	"github.com/fystack/mpcium/pkg/types"
)

type Transport interface {
	Send(to string, msg types.TaurusMessage) error
	Inbox() <-chan types.TaurusMessage
	Done() <-chan struct{}
	Close() error
}

// Memory implements Transport for local testing (per-party instance)
type Memory struct {
	selfID string
	peers  map[string]*Memory // reference to peers
	mu     sync.RWMutex

	inbox chan types.TaurusMessage
	done  chan struct{}
}

// NewMemoryParty creates a new memory transport for a party
func NewMemoryParty(selfID string) *Memory {
	return &Memory{
		selfID: selfID,
		peers:  make(map[string]*Memory),
		inbox:  make(chan types.TaurusMessage, 100),
		done:   make(chan struct{}),
	}
}

// LinkPeers links all parties together (must be called after all parties are created)
func LinkPeers(parties ...*Memory) {
	for _, p := range parties {
		for _, q := range parties {
			if p.selfID == q.selfID {
				continue
			}
			p.peers[q.selfID] = q
		}
	}
}

func (m *Memory) SelfID() string {
	return m.selfID
}

func (m *Memory) Send(to string, msg types.TaurusMessage) error {
	m.mu.RLock()
	peer, ok := m.peers[to]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	select {
	case peer.inbox <- msg:
	default:
		// drop if inbox full
	}
	return nil
}

func (m *Memory) Inbox() <-chan types.TaurusMessage {
	return m.inbox
}

func (m *Memory) Done() <-chan struct{} {
	return m.done
}

func (m *Memory) Close() error {
	close(m.done)
	close(m.inbox)
	return nil
}
