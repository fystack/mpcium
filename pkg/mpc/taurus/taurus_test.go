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

// taurusTest represents a 2-party in-memory network for Taurus
type taurusTest struct {
	parties []TaurusSession
	results map[string]chan any
}

func newTaurusTest(sid string, ids []party.ID) *taurusTest {
	t := &taurusTest{
		results: map[string]chan any{
			"keygen": make(chan any, len(ids)),
			"sign":   make(chan any, len(ids)),
		},
	}

	transports := make([]*Memory, len(ids))
	for i, id := range ids {
		transports[i] = NewMemoryParty(string(id))
	}
	LinkPeers(transports...)

	for i, id := range ids {
		t.parties = append(t.parties,
			NewTaprootSession(sid, id, ids, 1, transports[i], nil, nil))
	}

	return t
}

func (t *taurusTest) runAll(fn func(TaurusSession) (any, error), key string) {
	var wg sync.WaitGroup
	for _, p := range t.parties {
		wg.Add(1)
		go func(p TaurusSession) {
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
	close(t.results[key])
}

func drain[T any](ch chan any) []T {
	out := make([]T, 0, len(ch))
	for v := range ch {
		out = append(out, v.(T))
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

func TestTaurusParty(t *testing.T) {
	t.Parallel()

	// quick test, 2 nodes only
	ids := []party.ID{"node0", "node1"}
	sid := "cggmp21-fast"
	test := newTaurusTest(sid, ids)

	// --- Keygen (cached) ---
	test.runAll(func(p TaurusSession) (any, error) {
		return p.Keygen(context.Background())
	}, "keygen")

	// --- Sign ---
	msg := big.NewInt(42)
	test.runAll(func(p TaurusSession) (any, error) {
		return p.Sign(context.Background(), msg)
	}, "sign")

	sigs := drain[[]byte](test.results["sign"])
	assertAllBytesEqual(t, sigs)
}
