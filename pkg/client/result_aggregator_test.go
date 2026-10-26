package client

import (
	"sync"
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/event"
)

func newTestSigningAggregator(required int, timeout time.Duration) (*resultAggregator[event.SigningResultEvent], func() []event.SigningResultEvent) {
	var mu sync.Mutex
	var delivered []event.SigningResultEvent
	agg := signingResultAggregator(required, func(e event.SigningResultEvent) {
		mu.Lock()
		delivered = append(delivered, e)
		mu.Unlock()
	})
	agg.cfg.timeout = timeout
	return agg, func() []event.SigningResultEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]event.SigningResultEvent(nil), delivered...)
	}
}

func successResult(nodeID string) event.SigningResultEvent {
	return event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		TxID:       "tx1",
		R:          []byte{1},
		S:          []byte{2},
		NodeID:     nodeID,
	}
}

func TestResultAggregatorDeliversOnceAndDropsLateResults(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, 50*time.Millisecond)

	agg.Add(successResult("node0"))
	if got := len(delivered()); got != 0 {
		t.Fatalf("delivered %d results before threshold", got)
	}
	agg.Add(successResult("node1"))
	agg.Add(successResult("node2"))
	time.Sleep(100 * time.Millisecond)

	got := delivered()
	if len(got) != 1 || got[0].ResultType != event.ResultTypeSuccess {
		t.Fatalf("expected exactly one success delivery, got %+v", got)
	}
}

func TestResultAggregatorIgnoresDuplicateNode(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, 50*time.Millisecond)

	agg.Add(successResult("node0"))
	agg.Add(successResult("node0"))
	time.Sleep(100 * time.Millisecond)

	got := delivered()
	if len(got) != 1 || got[0].ErrorCode != event.ErrorCodeInsufficientNodeSignatures {
		t.Fatalf("expected one insufficient-signatures error, got %+v", got)
	}
}

func TestResultAggregatorDropsConflictingResult(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, 50*time.Millisecond)

	agg.Add(successResult("node0"))
	forged := successResult("node1")
	forged.R = []byte{9}
	agg.Add(forged)
	time.Sleep(100 * time.Millisecond)

	got := delivered()
	if len(got) != 1 || got[0].ErrorCode != event.ErrorCodeInsufficientNodeSignatures {
		t.Fatalf("expected one insufficient-signatures error, got %+v", got)
	}
}

func errorResult(nodeID, reason string) event.SigningResultEvent {
	return event.SigningResultEvent{
		ResultType:  event.ResultTypeError,
		TxID:        "tx1",
		ErrorReason: reason,
		NodeID:      nodeID,
	}
}

func TestResultAggregatorSingleErrorDoesNotPreemptSuccess(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, 50*time.Millisecond)

	agg.Add(errorResult("node0", "max deliveries"))
	agg.Add(successResult("node1"))
	agg.Add(successResult("node2"))
	time.Sleep(100 * time.Millisecond)

	got := delivered()
	if len(got) != 1 || got[0].ResultType != event.ResultTypeSuccess {
		t.Fatalf("expected exactly one success delivery, got %+v", got)
	}
}

func TestResultAggregatorDeliversErrorReportedByRequiredNodes(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, time.Hour)

	agg.Add(errorResult("node0", "first"))
	if got := len(delivered()); got != 0 {
		t.Fatalf("delivered %d results before error threshold", got)
	}
	agg.Add(errorResult("node1", "second"))
	agg.Add(successResult("node2"))

	got := delivered()
	if len(got) != 1 || got[0].ErrorReason != "first" {
		t.Fatalf("expected the first error delivered once, got %+v", got)
	}
}

func TestResultAggregatorDeliversLoneErrorOnTimeout(t *testing.T) {
	agg, delivered := newTestSigningAggregator(2, 50*time.Millisecond)

	agg.Add(errorResult("node0", "boom"))
	time.Sleep(100 * time.Millisecond)

	got := delivered()
	if len(got) != 1 || got[0].ErrorReason != "boom" {
		t.Fatalf("expected the lone error after timeout, got %+v", got)
	}
}

func TestReshareAggregatorUsesPerSessionThreshold(t *testing.T) {
	var delivered []event.ResharingResultEvent
	agg := reshareResultAggregator(func(e event.ResharingResultEvent) int {
		if e.SessionID == "small" {
			return 2
		}
		return 3
	}, func(e event.ResharingResultEvent) { delivered = append(delivered, e) })
	agg.cfg.timeout = time.Hour

	for _, node := range []string{"node0", "node1"} {
		agg.Add(event.ResharingResultEvent{SessionID: "small", WalletID: "w1", ResultType: event.ResultTypeSuccess, NodeID: node})
		agg.Add(event.ResharingResultEvent{SessionID: "large", WalletID: "w1", ResultType: event.ResultTypeSuccess, NodeID: node})
	}

	if len(delivered) != 1 || delivered[0].SessionID != "small" {
		t.Fatalf("expected only the small-committee session delivered, got %+v", delivered)
	}
}
