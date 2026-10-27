//go:build dklsbench

// Package dklsvstss benchmarks mpcium's tss-lib ECDSA backend against the DKLs23
// implementation (github.com/fystack/DKLs23, vendored under third_party/dkls23),
// running both in-process with local message routing (no network).
//
// tss-lib's ECDSA keygen needs Paillier "safe prime" preparams per party; generating
// them is slow (tens of seconds each) but, exactly as mpcium's Node does in production
// (see pkg/mpc/node.go generatePreParams), they are precomputed once and reused across
// keys — so that cost is paid once here too, outside the timed loop.
//
// Run with:
//
//	CGO_ENABLED=1 go test -tags dklsbench -bench . -benchtime=5x -run '^$' -timeout 30m ./benchmark/dklsvstss/...
package dklsvstss

import (
	"crypto/sha256"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
)

const (
	numParties = 2
	threshold  = 1 // 2-of-2
)

var (
	preParamsOnce sync.Once
	preParams     []*keygen.LocalPreParams
)

// sharedPreParams mirrors mpcium's Node: preparams are generated once and reused,
// so their (slow) generation cost is never part of a keygen benchmark.
func sharedPreParams(b *testing.B) []*keygen.LocalPreParams {
	b.Helper()
	preParamsOnce.Do(func() {
		preParams = make([]*keygen.LocalPreParams, numParties)
		errs := make([]error, numParties)
		var wg sync.WaitGroup
		for i := 0; i < numParties; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				preParams[i], errs[i] = keygen.GeneratePreParams(3 * time.Minute)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				b.Fatalf("generate preparams: %v", err)
			}
		}
	})
	return preParams
}

func BenchmarkTssLibKeygen(b *testing.B) {
	pp := sharedPreParams(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runTssKeygen(numParties, threshold, pp); err != nil {
			b.Fatalf("tss-lib keygen failed: %v", err)
		}
	}
}

func BenchmarkDklsKeygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shares, err := runDklsDKG(uint8(numParties), uint8(threshold+1))
		if err != nil {
			b.Fatalf("dkls keygen failed: %v", err)
		}
		for _, s := range shares {
			s.Free()
		}
	}
}

func BenchmarkTssLibSign(b *testing.B) {
	pp := sharedPreParams(b)
	keys, err := runTssKeygen(numParties, threshold, pp)
	if err != nil {
		b.Fatalf("tss-lib keygen (setup) failed: %v", err)
	}
	partyIDs := genTestPartyIDs(numParties)
	hashBytes := sha256.Sum256([]byte("dkls-vs-tss-bench"))
	msgHash := new(big.Int).SetBytes(hashBytes[:])

	signers := keys[:threshold+1]
	signerIDs := partyIDs[:threshold+1]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runTssSign(signers, signerIDs, threshold, msgHash); err != nil {
			b.Fatalf("tss-lib sign failed: %v", err)
		}
	}
}

func BenchmarkDklsSign(b *testing.B) {
	shares, err := runDklsDKG(uint8(numParties), uint8(threshold+1))
	if err != nil {
		b.Fatalf("dkls keygen (setup) failed: %v", err)
	}
	defer func() {
		for _, s := range shares {
			s.Free()
		}
	}()
	msgHash := sha256.Sum256([]byte("dkls-vs-tss-bench"))
	signers := shares[:threshold+1]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runDklsSign(signers, msgHash[:]); err != nil {
			b.Fatalf("dkls sign failed: %v", err)
		}
	}
}
