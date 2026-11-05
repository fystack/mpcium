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
	// ResultVerifyEnforce rejects unsigned or invalid results and waits for RequiredNodeSignatures matching results.
	ResultVerifyEnforce ResultVerifyMode = "enforce"
)

type resultVerifier struct {
	mode      ResultVerifyMode
	lookup    resultauth.KeyLookup
	required  int
	nodeCount int
}

func newResultVerifier(mode ResultVerifyMode, publicKeys map[string]string, required int) (resultVerifier, error) {
	switch mode {
	case "", ResultVerifyOff:
		return resultVerifier{mode: ResultVerifyOff, required: 1}, nil
	case ResultVerifyLog, ResultVerifyEnforce:
	default:
		return resultVerifier{}, fmt.Errorf("unknown result verify mode %q", mode)
	}

	if len(publicKeys) == 0 {
		return resultVerifier{}, fmt.Errorf("node public keys are required when result verify mode is %q", mode)
	}
	if required > len(publicKeys) {
		return resultVerifier{}, fmt.Errorf("required node signatures (%d) exceeds the number of node public keys (%d)", required, len(publicKeys))
	}
	lookup, err := resultauth.NewKeyLookup(publicKeys)
	if err != nil {
		return resultVerifier{}, err
	}
	if mode != ResultVerifyEnforce || required < 1 {
		required = 1
	}
	return resultVerifier{mode: mode, lookup: lookup, required: required, nodeCount: len(publicKeys)}, nil
}

func handleVerifiedResult[T any](
	verifier *resultVerifier,
	aggregator *resultauth.Aggregator[T],
	deliver func(T),
	msg messaging.Message,
	done func(error),
	result resultauth.Result[T],
) {
	if verifier.mode != ResultVerifyLog && verifier.mode != ResultVerifyEnforce {
		deliver(result.Event)
		done(nil)
		return
	}

	nodeID, err := resultauth.Verify(verifier.lookup, msg.Subject, msg.Data, msg.Header.Get)
	if err != nil {
		if verifier.mode == ResultVerifyEnforce {
			logger.Error("Rejecting result without a valid node signature", err, "subject", msg.Subject, "nodeID", nodeID)
			done(messaging.ErrPermament)
			return
		}
		logger.Warn("Result failed node signature verification", "subject", msg.Subject, "nodeID", nodeID, "error", err)
	}
	if verifier.mode == ResultVerifyLog {
		result.Required = 1
	}

	result.NodeID = nodeID
	result.Body = msg.Data
	result.Ack = func() { done(nil) }
	aggregator.Add(result)
}

func insufficientNodeSignaturesReason(got, required int) string {
	return fmt.Sprintf("result was signed by %d node(s) but %d are required; possible node failure or compromise", got, required)
}

func insufficientKeygenResult(result event.KeygenResultEvent, got, required int) event.KeygenResultEvent {
	result.ResultType = event.ResultTypeError
	result.ECDSAPubKey, result.EDDSAPubKey = nil, nil
	result.ErrorCode = string(event.ErrorCodeInsufficientNodeSignatures)
	result.ErrorReason = insufficientNodeSignaturesReason(got, required)
	return result
}

func insufficientSigningResult(result event.SigningResultEvent, got, required int) event.SigningResultEvent {
	result.ResultType = event.ResultTypeError
	result.R, result.S, result.SignatureRecovery, result.Signature = nil, nil, nil, nil
	result.ErrorCode = event.ErrorCodeInsufficientNodeSignatures
	result.ErrorReason = insufficientNodeSignaturesReason(got, required)
	return result
}

func insufficientReshareResult(result event.ResharingResultEvent, got, required int) event.ResharingResultEvent {
	result.ResultType = event.ResultTypeError
	result.PubKey = nil
	result.ErrorCode = string(event.ErrorCodeInsufficientNodeSignatures)
	result.ErrorReason = insufficientNodeSignaturesReason(got, required)
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
