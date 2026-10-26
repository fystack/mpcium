package client

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
)

const defaultResultAggregateTimeout = 15 * time.Second

// resultAggregatorConfig wires a result event type into the aggregator.
type resultAggregatorConfig[T any] struct {
	// required is the number of distinct nodes that must report the same
	// outcome before it is delivered (t+1).
	required int
	// requiredOf, when set, overrides required per result.
	requiredOf func(T) int
	// timeout is how long to wait for the remaining nodes after the first
	// verified result arrives.
	timeout time.Duration

	keyOf     func(T) string
	nodeOf    func(T) (string, []byte)
	rawOf     func(T) ([]byte, error)
	isSuccess func(T) bool
	// deliver hands a final result to the user callback.
	deliver func(T)
	// insufficient builds the error event delivered when fewer than
	// required nodes signed the same success result before the timeout.
	insufficient func(first T, got, required int) T
}

type pendingResult[T any] struct {
	required int

	success      T
	hasSuccess   bool
	successRaw   []byte
	successNodes map[string]struct{}

	firstError T
	hasError   bool
	errorNodes map[string]struct{}

	timer *time.Timer
}

// resultAggregator buffers node-signed result events and delivers the user
// callback exactly once per operation: when `required` distinct known nodes
// report the same success, when `required` nodes report an error, or when the
// timeout fires. A single compromised node cannot force either outcome.
// Events must already be signature-verified by the caller.
type resultAggregator[T any] struct {
	cfg     resultAggregatorConfig[T]
	mu      sync.Mutex
	pending map[string]*pendingResult[T]
	// completed holds recently finalized keys so late results from the remaining nodes are dropped.
	completed map[string]struct{}
}

func newResultAggregator[T any](cfg resultAggregatorConfig[T]) *resultAggregator[T] {
	if cfg.timeout <= 0 {
		cfg.timeout = defaultResultAggregateTimeout
	}
	return &resultAggregator[T]{cfg: cfg, pending: make(map[string]*pendingResult[T]), completed: make(map[string]struct{})}
}

func (a *resultAggregator[T]) requiredFor(ev T) int {
	if a.cfg.requiredOf != nil {
		return a.cfg.requiredOf(ev)
	}
	return a.cfg.required
}

// Add feeds one verified result event into the aggregator. It may call the
// deliver callback (from the calling goroutine, or from a timer goroutine
// when the aggregate times out).
func (a *resultAggregator[T]) Add(ev T) {
	cfg := a.cfg
	key := cfg.keyOf(ev)
	nodeID, _ := cfg.nodeOf(ev)

	a.mu.Lock()
	if _, done := a.completed[key]; done {
		a.mu.Unlock()
		return
	}
	p, ok := a.pending[key]
	if !ok {
		p = &pendingResult[T]{
			required:     a.requiredFor(ev),
			successNodes: make(map[string]struct{}),
			errorNodes:   make(map[string]struct{}),
		}
		if p.required > 1 {
			p.timer = time.AfterFunc(cfg.timeout, func() { a.expire(key) })
		}
		a.pending[key] = p
	}

	if !cfg.isSuccess(ev) {
		// Error payloads legitimately differ per node, so only the count of
		// distinct reporting nodes matters; the first error is delivered.
		if _, dup := p.errorNodes[nodeID]; dup {
			a.mu.Unlock()
			return
		}
		p.errorNodes[nodeID] = struct{}{}
		if !p.hasError {
			p.firstError, p.hasError = ev, true
		}
		if len(p.errorNodes) < p.required {
			a.mu.Unlock()
			return
		}
		a.finish(key, p)
		a.mu.Unlock()
		cfg.deliver(p.firstError)
		return
	}

	raw, err := cfg.rawOf(ev)
	if err != nil {
		a.mu.Unlock()
		logger.Error("Failed to canonicalize result event for aggregation", err)
		return
	}
	if !p.hasSuccess {
		p.success, p.successRaw, p.hasSuccess = ev, raw, true
	} else if !bytes.Equal(raw, p.successRaw) {
		a.mu.Unlock()
		logger.Warn("Conflicting result events for the same operation; dropping node's event",
			"key", key, "nodeID", nodeID)
		return
	}
	if _, dup := p.successNodes[nodeID]; dup {
		a.mu.Unlock()
		return
	}
	p.successNodes[nodeID] = struct{}{}
	if len(p.successNodes) < p.required {
		a.mu.Unlock()
		return
	}
	a.finish(key, p)
	a.mu.Unlock()
	cfg.deliver(p.success)
}

// finish must be called with a.mu held.
func (a *resultAggregator[T]) finish(key string, p *pendingResult[T]) {
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(a.pending, key)
	a.markCompleted(key)
}

// expire delivers an error result when not enough nodes agreed in time.
func (a *resultAggregator[T]) expire(key string) {
	a.mu.Lock()
	p, ok := a.pending[key]
	if !ok {
		a.mu.Unlock()
		return
	}
	a.finish(key, p)
	a.mu.Unlock()
	if p.hasSuccess {
		a.cfg.deliver(a.cfg.insufficient(p.success, len(p.successNodes), p.required))
		return
	}
	a.cfg.deliver(p.firstError)
}

// signingResultAggregator assembles the aggregator for signing results.
func signingResultAggregator(required int, deliver func(event.SigningResultEvent)) *resultAggregator[event.SigningResultEvent] {
	return newResultAggregator(resultAggregatorConfig[event.SigningResultEvent]{
		required: required,
		keyOf:    func(e event.SigningResultEvent) string { return e.TxID },
		nodeOf: func(e event.SigningResultEvent) (string, []byte) {
			return e.NodeID, e.ResultSignature
		},
		rawOf: func(e event.SigningResultEvent) ([]byte, error) { return e.Raw() },
		isSuccess: func(e event.SigningResultEvent) bool {
			return e.ResultType == event.ResultTypeSuccess
		},
		deliver: deliver,
		insufficient: func(e event.SigningResultEvent, got, required int) event.SigningResultEvent {
			e.ResultType = event.ResultTypeError
			e.ErrorCode = event.ErrorCodeInsufficientNodeSignatures
			e.R, e.S, e.SignatureRecovery, e.Signature = nil, nil, nil, nil
			e.ErrorReason = fmt.Sprintf(
				"result was signed by %d node(s) but %d are required; possible node failure or compromise",
				got, required,
			)
			return e
		},
	})
}

// walletResultAggregator assembles the aggregator for keygen results.
func walletResultAggregator(required int, deliver func(event.KeygenResultEvent)) *resultAggregator[event.KeygenResultEvent] {
	return newResultAggregator(resultAggregatorConfig[event.KeygenResultEvent]{
		required: required,
		keyOf:    func(e event.KeygenResultEvent) string { return e.WalletID },
		nodeOf: func(e event.KeygenResultEvent) (string, []byte) {
			return e.NodeID, e.ResultSignature
		},
		rawOf: func(e event.KeygenResultEvent) ([]byte, error) { return e.Raw() },
		isSuccess: func(e event.KeygenResultEvent) bool {
			return e.ResultType == event.ResultTypeSuccess
		},
		deliver: deliver,
		insufficient: func(e event.KeygenResultEvent, got, required int) event.KeygenResultEvent {
			e.ResultType = event.ResultTypeError
			e.ECDSAPubKey, e.EDDSAPubKey = nil, nil
			e.ErrorCode = string(event.ErrorCodeInsufficientNodeSignatures)
			e.ErrorReason = fmt.Sprintf(
				"result was signed by %d node(s) but %d are required; possible node failure or compromise",
				got, required,
			)
			return e
		},
	})
}

// reshareResultAggregator assembles the aggregator for resharing results.
// Only new-committee nodes report success, so requiredOf should reflect the requested new threshold.
func reshareResultAggregator(requiredOf func(event.ResharingResultEvent) int, deliver func(event.ResharingResultEvent)) *resultAggregator[event.ResharingResultEvent] {
	return newResultAggregator(resultAggregatorConfig[event.ResharingResultEvent]{
		requiredOf: requiredOf,
		keyOf:      func(e event.ResharingResultEvent) string { return e.WalletID + ":" + e.SessionID },
		nodeOf: func(e event.ResharingResultEvent) (string, []byte) {
			return e.NodeID, e.ResultSignature
		},
		rawOf: func(e event.ResharingResultEvent) ([]byte, error) { return e.Raw() },
		isSuccess: func(e event.ResharingResultEvent) bool {
			return e.ResultType == event.ResultTypeSuccess
		},
		deliver: deliver,
		insufficient: func(e event.ResharingResultEvent, got, required int) event.ResharingResultEvent {
			e.ResultType = event.ResultTypeError
			e.PubKey = nil
			e.ErrorCode = string(event.ErrorCodeInsufficientNodeSignatures)
			e.ErrorReason = fmt.Sprintf(
				"result was signed by %d node(s) but %d are required; possible node failure or compromise",
				got, required,
			)
			return e
		},
	})
}

// markCompleted must be called with a.mu held.
func (a *resultAggregator[T]) markCompleted(key string) {
	a.completed[key] = struct{}{}
	time.AfterFunc(a.cfg.timeout, func() {
		a.mu.Lock()
		delete(a.completed, key)
		a.mu.Unlock()
	})
}
