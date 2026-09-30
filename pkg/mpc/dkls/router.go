//go:build dkls

package dkls

import (
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

const (
	earlyBufferTTL      = 60 * time.Second
	earlyBufferSweep    = 15 * time.Second
	earlyBufferPerKey   = 64
	earlyBufferMaxKeys  = 200000
	sessionInboxBacklog = 64
)

type earlyBuffer struct {
	msgs    []types.DklsMessage
	created time.Time
}

// Bundles that beat the local session are buffered, so sessions need no peer-ready barrier.
type Router struct {
	selfID string
	auth   MessageAuthenticator
	prefix string

	mu       sync.Mutex
	sessions map[string]chan types.DklsMessage
	early    map[string]*earlyBuffer

	sub  messaging.Subscription
	stop chan struct{}
}

func NewRouter(selfID string, pubsub messaging.PubSub, auth MessageAuthenticator) (*Router, error) {
	r := &Router{
		selfID:   selfID,
		auth:     auth,
		prefix:   subjectPrefix(selfID),
		sessions: make(map[string]chan types.DklsMessage),
		early:    make(map[string]*earlyBuffer),
		stop:     make(chan struct{}),
	}
	sub, err := pubsub.Subscribe(r.prefix+">", func(msg *nats.Msg) {
		go r.handle(msg.Subject, msg.Data)
	})
	if err != nil {
		return nil, err
	}
	r.sub = sub
	go r.sweepLoop()
	return r, nil
}

func subjectPrefix(nodeID string) string { return "dkls.to." + nodeID + "." }

func sessionSubject(to string, act Act, sessionKey string) string {
	return subjectPrefix(to) + string(act) + "." + sessionKey
}

func routeKey(act Act, sessionKey string) string { return string(act) + "." + sessionKey }

func (r *Router) Close() {
	close(r.stop)
	if r.sub != nil {
		_ = r.sub.Unsubscribe()
	}
}

func (r *Router) register(key string) chan types.DklsMessage {
	inbox := make(chan types.DklsMessage, sessionInboxBacklog)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[key] = inbox
	if buf, ok := r.early[key]; ok {
		delete(r.early, key)
		for _, m := range buf.msgs {
			select {
			case inbox <- m:
			default:
			}
		}
	}
	return inbox
}

func (r *Router) unregister(key string, inbox chan types.DklsMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[key] == inbox {
		delete(r.sessions, key)
	}
	close(inbox)
}

func (r *Router) handle(subject string, data []byte) {
	key := strings.TrimPrefix(subject, r.prefix)
	var msg types.DklsMessage
	if err := msg.UnmarshalWire(data); err != nil {
		logger.Warn("failed to decode dkls message", "err", err.Error())
		return
	}
	if msg.From == r.selfID {
		return
	}
	msg.Route = key
	msg.To = r.selfID
	if err := r.auth.VerifyDklsMessage(&msg); err != nil {
		logger.Warn("failed to verify dkls message", "err", err.Error())
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if inbox, ok := r.sessions[key]; ok {
		select {
		case inbox <- msg:
		default:
			logger.Warn("dropping inbound dkls message, inbox full", "key", key)
		}
		return
	}
	buf, ok := r.early[key]
	if !ok {
		if len(r.early) >= earlyBufferMaxKeys {
			return
		}
		buf = &earlyBuffer{created: time.Now()}
		r.early[key] = buf
	}
	if len(buf.msgs) < earlyBufferPerKey {
		buf.msgs = append(buf.msgs, msg)
	}
}

func (r *Router) sweepLoop() {
	ticker := time.NewTicker(earlyBufferSweep)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for key, buf := range r.early {
				if now.Sub(buf.created) > earlyBufferTTL {
					delete(r.early, key)
				}
			}
			r.mu.Unlock()
		}
	}
}
