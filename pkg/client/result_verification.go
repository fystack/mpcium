package client

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/resultauth"
)

type ResultVerifyMode string

const (
	ResultVerifyOff ResultVerifyMode = "off"
	// ResultVerifyLog checks signatures and logs failures but still delivers every result.
	ResultVerifyLog ResultVerifyMode = "log"
	// ResultVerifyEnforce rejects unsigned or invalid results.
	ResultVerifyEnforce ResultVerifyMode = "enforce"
)

type resultVerifier struct {
	mode           ResultVerifyMode
	lookup         resultauth.KeyLookup
	keygenRequired int
}

func newResultVerifier(mode ResultVerifyMode, publicKeys map[string]string, keygenRequired int) (resultVerifier, error) {
	switch mode {
	case "", ResultVerifyOff:
		if keygenRequired > 1 {
			return resultVerifier{}, fmt.Errorf("keygen required node signatures needs result verify mode %q", ResultVerifyEnforce)
		}
		return resultVerifier{mode: ResultVerifyOff, keygenRequired: 1}, nil
	case ResultVerifyLog, ResultVerifyEnforce:
	default:
		return resultVerifier{}, fmt.Errorf("unknown result verify mode %q", mode)
	}

	if len(publicKeys) == 0 {
		return resultVerifier{}, fmt.Errorf("node public keys are required when result verify mode is %q", mode)
	}
	if keygenRequired > 1 && mode != ResultVerifyEnforce {
		return resultVerifier{}, fmt.Errorf("keygen required node signatures needs result verify mode %q", ResultVerifyEnforce)
	}
	if keygenRequired > len(publicKeys) {
		return resultVerifier{}, fmt.Errorf("keygen required node signatures (%d) exceeds the number of node public keys (%d)", keygenRequired, len(publicKeys))
	}
	lookup, err := resultauth.NewKeyLookup(publicKeys)
	if err != nil {
		return resultVerifier{}, err
	}
	return resultVerifier{mode: mode, lookup: lookup, keygenRequired: max(keygenRequired, 1)}, nil
}

// check verifies a result's node signature. It returns false, after settling msg, when enforce rejects it.
func (v *resultVerifier) check(msg messaging.Message, done func(error)) (string, bool) {
	if v.mode != ResultVerifyLog && v.mode != ResultVerifyEnforce {
		return "", true
	}
	nodeID, err := resultauth.Verify(v.lookup, msg.Subject, msg.Data, msg.Header.Get)
	if err == nil {
		return nodeID, true
	}
	if v.mode == ResultVerifyEnforce {
		logger.Error("Rejecting result without a valid node signature", err, "subject", msg.Subject, "nodeID", nodeID)
		done(messaging.ErrPermament)
		return nodeID, false
	}
	logger.Warn("Result failed node signature verification", "subject", msg.Subject, "nodeID", nodeID, "error", err)
	return nodeID, true
}

func insufficientKeygenResult(result event.KeygenResultEvent, got, required int) event.KeygenResultEvent {
	result.ResultType = event.ResultTypeError
	result.ECDSAPubKey, result.EDDSAPubKey = nil, nil
	result.ErrorCode = string(event.ErrorCodeInsufficientNodeSignatures)
	result.ErrorReason = fmt.Sprintf("result was signed by %d node(s) but %d are required; possible node failure or compromise", got, required)
	return result
}

// sharedAggregator spans subscriptions because JetStream splits a consumer's node copies across them; the latest callback wins.
type sharedAggregator[T any] struct {
	once       sync.Once
	aggregator *resultauth.Aggregator[T]
	callback   atomic.Pointer[func(T)]
}

func (s *sharedAggregator[T]) register(callback func(T), cfg resultauth.AggregatorConfig[T]) *resultauth.Aggregator[T] {
	s.callback.Store(&callback)
	s.once.Do(func() {
		cfg.Deliver = func(result T) { (*s.callback.Load())(result) }
		s.aggregator = resultauth.NewAggregator(cfg)
	})
	return s.aggregator
}
