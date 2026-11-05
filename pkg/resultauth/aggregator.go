package resultauth

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
)

const (
	DefaultAggregateTimeout = 15 * time.Second
	// DefaultRememberedOutcomes bounds how many finished keys are kept to recognise late copies.
	DefaultRememberedOutcomes = 50_000
)

type AggregatorConfig[T any] struct {
	Timeout            time.Duration
	RememberedOutcomes int
	Deliver            func(T)
	// Insufficient builds the error delivered when no success body reached the required count before the timeout.
	Insufficient func(largest T, got, required int) T
	// Completed, when set, is called once per round when its result is finalized.
	Completed func(key string)
}

// Result is one verified node copy; Ack settles its message once the copy is delivered or dropped.
type Result[T any] struct {
	Key      string
	Required int
	NodeID   string
	Body     []byte
	Success  bool
	Event    T
	Ack      func()
}

type successGroup[T any] struct {
	event T
	nodes map[string]struct{}
}

type round[T any] struct {
	required  int
	nodes     map[string]struct{}
	successes map[[sha256.Size]byte]*successGroup[T]

	firstError T
	hasError   bool
	errorCount int

	acks  []func()
	timer *time.Timer
}

// outcome remembers which nodes a finished key heard from: a further copy from one of them is a new attempt.
type outcome struct {
	succeeded bool
	nodes     map[string]struct{}
}

// Aggregator delivers one result per round, once Required nodes agree or the timeout fires; results must be verified.
type Aggregator[T any] struct {
	cfg       AggregatorConfig[T]
	mu        sync.Mutex
	deliverMu sync.Mutex
	rounds    map[string]*round[T]
	outcomes  map[string]*outcome
	order     []string
}

func NewAggregator[T any](cfg AggregatorConfig[T]) *Aggregator[T] {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultAggregateTimeout
	}
	if cfg.RememberedOutcomes <= 0 {
		cfg.RememberedOutcomes = DefaultRememberedOutcomes
	}
	return &Aggregator[T]{
		cfg:      cfg,
		rounds:   make(map[string]*round[T]),
		outcomes: make(map[string]*outcome),
	}
}

func (a *Aggregator[T]) Add(result Result[T]) {
	a.mu.Lock()
	r := a.roundFor(result)
	if r == nil {
		a.mu.Unlock()
		settle(result.Ack)
		return
	}
	r.acks = append(r.acks, result.Ack)
	if _, dup := r.nodes[result.NodeID]; dup {
		a.mu.Unlock()
		return
	}
	r.nodes[result.NodeID] = struct{}{}
	finished, outcome := a.record(result, r)
	a.mu.Unlock()
	if finished {
		a.complete(r, outcome)
	}
}

// roundFor returns the open round for the result, or nil for a late copy of a finished key. Must hold a.mu.
func (a *Aggregator[T]) roundFor(result Result[T]) *round[T] {
	if r, ok := a.rounds[result.Key]; ok {
		return r
	}
	if done, finished := a.outcomes[result.Key]; finished {
		if _, repeated := done.nodes[result.NodeID]; !repeated {
			done.nodes[result.NodeID] = struct{}{}
			return nil
		}
	}
	r := &round[T]{
		required:  max(result.Required, 1),
		nodes:     make(map[string]struct{}),
		successes: make(map[[sha256.Size]byte]*successGroup[T]),
	}
	if r.required > 1 {
		key := result.Key
		r.timer = time.AfterFunc(a.cfg.Timeout, func() { a.expire(key) })
	}
	a.rounds[result.Key] = r
	return r
}

// record counts one node's copy and finishes the round once it reaches quorum. Must hold a.mu.
func (a *Aggregator[T]) record(result Result[T], r *round[T]) (bool, T) {
	var none T
	if !result.Success {
		// Error payloads legitimately differ per node, so only distinct reporters are counted.
		r.errorCount++
		if !r.hasError {
			r.firstError, r.hasError = result.Event, true
		}
		if r.errorCount < r.required {
			return false, none
		}
		a.finish(result.Key, r, false)
		return true, r.firstError
	}

	bodyHash := sha256.Sum256(result.Body)
	group, ok := r.successes[bodyHash]
	if !ok {
		if len(r.successes) > 0 {
			logger.Warn("Nodes sent different results for the same operation", "key", result.Key, "nodeID", result.NodeID)
		}
		group = &successGroup[T]{event: result.Event, nodes: make(map[string]struct{})}
		r.successes[bodyHash] = group
	}
	group.nodes[result.NodeID] = struct{}{}
	if len(group.nodes) < r.required {
		return false, none
	}
	a.finish(result.Key, r, true)
	return true, group.event
}

// finish must be called with a.mu held.
func (a *Aggregator[T]) finish(key string, r *round[T], succeeded bool) {
	if r.timer != nil {
		r.timer.Stop()
	}
	delete(a.rounds, key)
	if a.cfg.Completed != nil {
		a.cfg.Completed(key)
	}
	if _, known := a.outcomes[key]; !known {
		a.order = append(a.order, key)
		if len(a.order) > a.cfg.RememberedOutcomes {
			delete(a.outcomes, a.order[0])
			a.order = a.order[1:]
		}
	}
	a.outcomes[key] = &outcome{succeeded: succeeded, nodes: r.nodes}
}

// complete delivers outside a.mu, one result at a time, and settles the round's messages only afterwards.
func (a *Aggregator[T]) complete(r *round[T], result T) {
	a.deliverMu.Lock()
	a.cfg.Deliver(result)
	a.deliverMu.Unlock()
	for _, ack := range r.acks {
		settle(ack)
	}
}

func (a *Aggregator[T]) expire(key string) {
	a.mu.Lock()
	r, ok := a.rounds[key]
	if !ok {
		a.mu.Unlock()
		return
	}
	previous := a.outcomes[key]
	a.finish(key, r, false)
	if previous != nil && previous.succeeded {
		// A round that misses quorum after a delivered success must not report that success as failed.
		a.outcomes[key] = previous
		a.mu.Unlock()
		logger.Warn("Dropping result round that missed quorum after a delivered success", "key", key)
		for _, ack := range r.acks {
			settle(ack)
		}
		return
	}
	a.mu.Unlock()

	var largest *successGroup[T]
	for _, group := range r.successes {
		if largest == nil || len(group.nodes) > len(largest.nodes) {
			largest = group
		}
	}
	if largest != nil {
		a.complete(r, a.cfg.Insufficient(largest.event, len(largest.nodes), r.required))
		return
	}
	a.complete(r, r.firstError)
}

func settle(ack func()) {
	if ack != nil {
		ack()
	}
}
