//go:build dkls && dklsnats

// Needs a NATS server at DKLS_TEST_NATS_URL (default 127.0.0.1:14222); `make test-dkls-nats` starts one.
package dkls

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
)

func natsURL() string {
	if v := os.Getenv("DKLS_TEST_NATS_URL"); v != "" {
		return v
	}
	return "nats://127.0.0.1:14222"
}

func newNATSServices(t testing.TB, nodeIDs []string) map[string]*Service {
	t.Helper()
	conn, err := nats.Connect(natsURL())
	if err != nil {
		t.Skipf("no NATS server at %s: %v", natsURL(), err)
	}
	t.Cleanup(conn.Close)

	services := newTestServices(t, messaging.NewNATSPubSub(conn), nodeIDs, nodeIDs)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return services
}

func keygenAll(t testing.TB, services map[string]*Service, walletID string, threshold int) KeyResult {
	t.Helper()
	var wg sync.WaitGroup
	results := make(chan KeyResult, len(services))
	errs := make(chan error, len(services))
	for _, svc := range services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := svc.Keygen(walletID, threshold)
			results <- res
			errs <- err
		}()
	}
	wg.Wait()
	for range services {
		if err := <-errs; err != nil {
			t.Fatalf("keygen failed: %v", err)
		}
	}
	return <-results
}

func signAll(t testing.TB, services map[string]*Service, signers []string, walletID, txID string, hash []byte, path []uint32) []Signature {
	t.Helper()
	sigs := make([]Signature, len(signers))
	errs := make([]error, len(signers))
	var wg sync.WaitGroup
	for i, id := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sigs[i], errs[i] = services[id].Sign(walletID, txID, hash, path)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
	}
	return sigs
}

func TestKeygenAndSign_RealNATS_3of3(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	services := newNATSServices(t, nodeIDs)
	master := keygenAll(t, services, "nats-wallet-1", 2)

	hash := sha256.Sum256([]byte("real-nats-integration-test"))
	for _, sig := range signAll(t, services, nodeIDs, "nats-wallet-1", "tx-1", hash[:], nil) {
		verifySignature(t, sig, hash[:], parsePubKey(t, master.PubKey))
	}

	child := bip32DerivePublic(t, compressXY(t, master.PubKey), master.ChainCode, []uint32{3, 9})
	for _, sig := range signAll(t, services, nodeIDs, "nats-wallet-1", "tx-2", hash[:], []uint32{3, 9}) {
		verifySignature(t, sig, hash[:], child)
	}
}

func BenchmarkKeygen_RealNATS_3of3(b *testing.B) {
	services := newNATSServices(b, []string{"node-a", "node-b", "node-c"})
	for i := 0; b.Loop(); i++ {
		keygenAll(b, services, fmt.Sprintf("bench-kg-wallet-%d", i), 2)
	}
}

func BenchmarkSign_RealNATS_3of3(b *testing.B) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	services := newNATSServices(b, nodeIDs)
	keygenAll(b, services, "bench-sign-wallet", 2)

	for i := 0; b.Loop(); i++ {
		hash := sha256.Sum256(fmt.Appendf(nil, "bench-sign-msg-%d", i))
		signAll(b, services, nodeIDs, "bench-sign-wallet", fmt.Sprintf("tx-%d", i), hash[:], nil)
	}
}
