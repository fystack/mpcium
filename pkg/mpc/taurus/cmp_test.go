package taurus

import (
	"bytes"
	"context"
	"math/big"
	"sync"
	"testing"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
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

	// --- Reshare ---
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Reshare(context.Background())
	}, "reshare")

	reshareResults := drain[types.ReshareData](test.results["reshare"])
	assertReshareDataConsistent(t, reshareResults)

	// --- Sign 2 (after reshare) ---
	msg = big.NewInt(2)
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Sign(context.Background(), msg)
	}, "sign")

	sigs2 := drain[[]byte](test.results["sign"])
	assertAllBytesEqual(t, sigs2)
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

func assertReshareDataConsistent(t *testing.T, reshareResults []types.ReshareData) {
	if len(reshareResults) == 0 {
		t.Fatal("no reshare results to compare")
	}

	first := reshareResults[0]
	t.Logf("Reshare result - SID: %s, Type: %s, Threshold: %d, PubKey length: %d",
		first.SID, first.Type, first.Threshold, len(first.PubKeyBytes))

	// All parties should have the same public key after reshare
	for i, result := range reshareResults[1:] {
		if !bytes.Equal(first.PubKeyBytes, result.PubKeyBytes) {
			t.Fatalf("public keys not equal after reshare at index %d", i+1)
		}
		if first.SID != result.SID {
			t.Fatalf("session IDs not equal after reshare at index %d", i+1)
		}
		if first.Type != result.Type {
			t.Fatalf("key types not equal after reshare at index %d", i+1)
		}
		if first.Threshold != result.Threshold {
			t.Fatalf("thresholds not equal after reshare at index %d", i+1)
		}
	}

	// Validate that we have valid public key data
	if len(first.PubKeyBytes) == 0 {
		t.Fatal("public key bytes should not be empty after reshare")
	}

	// Validate key type
	if first.Type != "taurus_cmp" {
		t.Fatalf("expected key type 'taurus_cmp', got '%s'", first.Type)
	}

	t.Logf("Reshare data consistency validation passed for %d parties", len(reshareResults))
}

func TestCmpResharing(t *testing.T) {
	sid := "test-reshare-session-456"
	ids := []party.ID{"node0", "node1", "node2"}
	test := newCmpTest(sid, ids)

	// Phase 1: Initial key generation
	t.Log("Phase 1: Initial key generation")
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Keygen(context.Background())
	}, "keygen")

	keygenResults := drain[types.KeyData](test.results["keygen"])
	t.Logf("Generated %d keys", len(keygenResults))

	// Verify initial keygen results
	if len(keygenResults) != len(ids) {
		t.Fatalf("expected %d keygen results, got %d", len(ids), len(keygenResults))
	}

	// Phase 2: Initial signing to verify keys work
	t.Log("Phase 2: Initial signing verification")
	msg1 := big.NewInt(42)
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Sign(context.Background(), msg1)
	}, "sign")

	sigs1 := drain[[]byte](test.results["sign"])
	assertAllBytesEqual(t, sigs1)
	t.Logf("Initial signing successful with %d signatures", len(sigs1))

	// Phase 3: Reshare/refresh keys
	t.Log("Phase 3: Resharing/refreshing keys")
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Reshare(context.Background())
	}, "reshare")

	reshareResults := drain[types.ReshareData](test.results["reshare"])
	assertReshareDataConsistent(t, reshareResults)
	t.Logf("Resharing successful with %d results", len(reshareResults))

	// Phase 4: Signing after reshare to verify keys still work
	t.Log("Phase 4: Signing after reshare")
	msg2 := big.NewInt(84)
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Sign(context.Background(), msg2)
	}, "sign")

	sigs2 := drain[[]byte](test.results["sign"])
	assertAllBytesEqual(t, sigs2)
	t.Logf("Post-reshare signing successful with %d signatures", len(sigs2))

	// Phase 5: Verify public keys remain the same after reshare
	t.Log("Phase 5: Public key consistency verification")
	originalPubKey := keygenResults[0].PubKeyBytes
	resharedPubKey := reshareResults[0].PubKeyBytes

	if !bytes.Equal(originalPubKey, resharedPubKey) {
		t.Fatal("Public key changed after reshare - this should not happen in CMP refresh")
	}

	t.Log("All resharing tests passed successfully")
}

func TestCmpMultipleReshares(t *testing.T) {
	sid := "test-multi-reshare-789"
	ids := []party.ID{"node0", "node1", "node2"}
	test := newCmpTest(sid, ids)

	// Initial keygen
	t.Log("Initial key generation")
	test.runAll(func(p *CmpParty) (any, error) {
		return p.Keygen(context.Background())
	}, "keygen")

	keygenResults := drain[types.KeyData](test.results["keygen"])
	originalPubKey := keygenResults[0].PubKeyBytes

	// Perform multiple reshares
	numReshares := 3
	for i := 1; i <= numReshares; i++ {
		t.Logf("Reshare iteration %d/%d", i, numReshares)

		// Reshare
		test.runAll(func(p *CmpParty) (any, error) {
			return p.Reshare(context.Background())
		}, "reshare")

		reshareResults := drain[types.ReshareData](test.results["reshare"])
		assertReshareDataConsistent(t, reshareResults)

		// Verify public key consistency
		if !bytes.Equal(originalPubKey, reshareResults[0].PubKeyBytes) {
			t.Fatalf("Public key changed after reshare %d", i)
		}

		// Test signing after each reshare
		testMsg := big.NewInt(int64(100 + i))
		test.runAll(func(p *CmpParty) (any, error) {
			return p.Sign(context.Background(), testMsg)
		}, "sign")

		sigs := drain[[]byte](test.results["sign"])
		assertAllBytesEqual(t, sigs)
		t.Logf("Signing after reshare %d successful", i)
	}

	t.Logf("Multiple reshares test passed (%d reshares)", numReshares)
}
