package resultauth

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testEvent struct {
	Value   string
	Success bool
	Reason  string
}

type deliveries struct {
	mu     sync.Mutex
	events []testEvent
	done   chan struct{}
}

func newDeliveries() *deliveries { return &deliveries{done: make(chan struct{}, 16)} }

func (d *deliveries) deliver(ev testEvent) {
	d.mu.Lock()
	d.events = append(d.events, ev)
	d.mu.Unlock()
	d.done <- struct{}{}
}

func (d *deliveries) snapshot() []testEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]testEvent(nil), d.events...)
}

func newTestAggregator(d *deliveries, timeout time.Duration) *Aggregator[testEvent] {
	return NewAggregator(AggregatorConfig[testEvent]{
		Timeout: timeout,
		Deliver: d.deliver,
		Insufficient: func(first testEvent, got, required int) testEvent {
			return testEvent{Value: first.Value, Success: false, Reason: "insufficient"}
		},
	})
}

func successResult(node, body string) Result[testEvent] {
	return Result[testEvent]{Key: "op-1", Required: 2, NodeID: node, Body: []byte(body), Success: true, Event: testEvent{Value: body, Success: true}}
}

func errorResult(node, reason string) Result[testEvent] {
	return Result[testEvent]{Key: "op-1", Required: 2, NodeID: node, Body: []byte(reason), Event: testEvent{Reason: reason}}
}

func TestAggregatorDeliversAfterRequiredMatchingSuccesses(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(successResult("node0", "sig"))
	require.Empty(t, d.snapshot())
	a.Add(successResult("node0", "sig"))
	require.Empty(t, d.snapshot(), "the same node must not count twice")
	a.Add(successResult("node1", "sig"))
	a.Add(successResult("node2", "sig"))

	require.Equal(t, []testEvent{{Value: "sig", Success: true}}, d.snapshot())
}

func TestAggregatorIgnoresConflictingSuccess(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(successResult("node0", "sig"))
	a.Add(successResult("node1", "forged"))
	require.Empty(t, d.snapshot())
	a.Add(successResult("node2", "sig"))

	require.Equal(t, []testEvent{{Value: "sig", Success: true}}, d.snapshot())
}

func TestAggregatorForgedFirstCopyDoesNotBlockHonestQuorum(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(successResult("node0", "forged"))
	a.Add(successResult("node1", "sig"))
	a.Add(successResult("node2", "sig"))

	require.Equal(t, []testEvent{{Value: "sig", Success: true}}, d.snapshot())
}

func TestAggregatorSettlesCopiesAfterDelivery(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)
	var settled []string
	withAck := func(r Result[testEvent]) Result[testEvent] {
		r.Ack = func() { settled = append(settled, r.NodeID) }
		return r
	}

	a.Add(withAck(successResult("node0", "sig")))
	require.Empty(t, settled)
	a.Add(withAck(successResult("node1", "sig")))
	require.Equal(t, []string{"node0", "node1"}, settled)
	a.Add(withAck(successResult("node2", "sig")))
	require.Equal(t, []string{"node0", "node1", "node2"}, settled)
}

func TestAggregatorLateCopyAfterTimeoutIsNotReportedAsFailure(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, 20*time.Millisecond)

	a.Add(successResult("node0", "sig"))
	a.Add(successResult("node1", "sig"))
	time.Sleep(50 * time.Millisecond)
	a.Add(successResult("node2", "sig"))
	a.Add(successResult("node0", "forged-after-delivery"))
	time.Sleep(50 * time.Millisecond)

	require.Equal(t, []testEvent{{Value: "sig", Success: true}}, d.snapshot())
}

func TestAggregatorRetryAfterErrorDelivers(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(errorResult("node0", "timeout"))
	a.Add(errorResult("node1", "timeout"))
	a.Add(successResult("node0", "sig"))
	a.Add(successResult("node1", "sig"))

	require.Equal(t, []testEvent{{Reason: "timeout"}, {Value: "sig", Success: true}}, d.snapshot())
}

func TestAggregatorReplayFromSameNodesDeliversAgain(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(successResult("node0", "stored"))
	a.Add(successResult("node1", "stored"))
	a.Add(successResult("node0", "stored"))
	a.Add(successResult("node1", "stored"))

	require.Len(t, d.snapshot(), 2)
}

func TestAggregatorForgetsOldestOutcomes(t *testing.T) {
	d := newDeliveries()
	a := NewAggregator(AggregatorConfig[testEvent]{RememberedOutcomes: 2, Deliver: d.deliver, Insufficient: func(first testEvent, _, _ int) testEvent { return first }})
	for _, key := range []string{"op-1", "op-2", "op-3"} {
		a.Add(Result[testEvent]{Key: key, Required: 1, NodeID: "node0", Body: []byte(key), Success: true})
	}
	require.Len(t, a.outcomes, 2)
	require.NotContains(t, a.outcomes, "op-1")
}

func TestAggregatorDeliversErrorFromRequiredNodes(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, time.Minute)

	a.Add(errorResult("node0", "timeout"))
	a.Add(errorResult("node1", "aborted"))

	require.Equal(t, []testEvent{{Reason: "timeout"}}, d.snapshot())
}

func TestAggregatorTimesOutWithInsufficientSignatures(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, 20*time.Millisecond)

	a.Add(successResult("node0", "sig"))
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("aggregator did not time out")
	}

	require.Equal(t, []testEvent{{Value: "sig", Reason: "insufficient"}}, d.snapshot())
}

func TestAggregatorTimesOutWithSingleError(t *testing.T) {
	d := newDeliveries()
	a := newTestAggregator(d, 20*time.Millisecond)

	a.Add(errorResult("node0", "timeout"))
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("aggregator did not time out")
	}

	require.Equal(t, []testEvent{{Reason: "timeout"}}, d.snapshot())
}

func TestAggregatorDropsLateResultsAndReportsCompletion(t *testing.T) {
	d := newDeliveries()
	var completed []string
	a := NewAggregator(AggregatorConfig[testEvent]{
		Timeout:      time.Minute,
		Deliver:      d.deliver,
		Insufficient: func(first testEvent, _, _ int) testEvent { return first },
		Completed:    func(key string) { completed = append(completed, key) },
	})

	a.Add(successResult("node0", "sig"))
	a.Add(successResult("node1", "sig"))
	a.Add(successResult("node2", "sig"))
	a.Add(errorResult("node2", "late"))

	require.Len(t, d.snapshot(), 1)
	require.Equal(t, []string{"op-1"}, completed)
}
