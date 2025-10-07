package taurus

import (
	"bytes"
	"context"
	"math/big"
	"sync"
	"testing"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type cmpTest struct {
	parties []*CmpParty
	results map[string]chan any
}

func newCmpTest(sid string, ids []party.ID) *cmpTest {
	t := &cmpTest{
		results: map[string]chan any{
			"keygen":  make(chan any, len(ids)),
			"sign":    make(chan any, len(ids)),
			"reshare": make(chan any, len(ids)),
		},
	}

	// Create all memory transports first
	transports := make([]*Memory, len(ids))
	for i, id := range ids {
		transports[i] = NewMemoryParty(string(id))
	}

	// Link all peers together
	LinkPeers(transports...)

	// Create parties with linked transports
	for i, id := range ids {
		adapter := NewTaurusNetworkAdapter(sid, id, transports[i], ids)
		t.parties = append(t.parties, NewCmpParty(sid, id, ids, 2,
			nil, adapter, nil, nil))
	}

	return t
}

func (t *cmpTest) runAll(fn func(*CmpParty) (any, error), key string) {
	var wg sync.WaitGroup
	for _, p := range t.parties {
		wg.Add(1)
		go func(p *CmpParty) {
			defer wg.Done()
			res, err := fn(p)
			if err != nil {
				logger.Error("operation failed", err)
				return
			}
			t.results[key] <- res
		}(p)
	}
	wg.Wait()
}

func TestCmpParty(t *testing.T) {
	sid := "test-session-123"
	ids := []party.ID{"node0", "node1", "node2"}
	test := newCmpTest(sid, ids)

	// --- Keygen ---
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Keygen(context.Background())
	}, "keygen")

	// --- Sign 1 ---
	msg := big.NewInt(1)
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Sign(context.Background(), msg)
	}, "sign")

	sigs := drain[[]byte](test.results["sign"])
	assertAllBytesEqual(t, sigs)

	// // --- Reshare ---
	// test.runAll(func(p *CmpParty) (any, error) {
	// 	return p.Reshare(context.Background())
	// }, "reshare")

	// // // --- Sign 2 ---
	// msg = big.NewInt(2)
	// test.runAll(func(p *CmpParty) (any, error) {
	// 	return p.Sign(context.Background(), msg)
	// }, "sign")
}

func drain[T any](ch chan any) []T {
	n := len(ch)
	out := make([]T, n)
	for i := 0; i < n; i++ {
		out[i] = (<-ch).(T)
	}
	return out
}

func assertAllBytesEqual(t *testing.T, vals [][]byte) {
	if len(vals) == 0 {
		t.Fatal("no values to compare")
	}
	first := vals[0]
	for i, v := range vals[1:] {
		if !bytes.Equal(first, v) {
			t.Fatalf("byte slices not equal at index %d", i+1)
		}
	}
}
