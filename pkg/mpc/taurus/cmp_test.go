package taurus

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func TestCmpParty(t *testing.T) {
	sid := "test-session-123"
	parties := []string{"party1", "party2", "party3"}
	ids := make([]party.ID, len(parties))
	for i, id := range parties {
		ids[i] = party.ID(id)
	}
	pl := pool.NewPool(0)

	natsConn, err := nats.Connect("nats://localhost:4223")
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}

	pubsub := messaging.NewNATSPubSub(natsConn)

	// networks + adapters
	network1 := NewNATSTransport(sid, party.ID("party1"), pubsub)
	network2 := NewNATSTransport(sid, party.ID("party2"), pubsub)
	network3 := NewNATSTransport(sid, party.ID("party3"), pubsub)

	adapter1 := NewTaurusNetworkAdapter(sid, "party1", network1, ids)
	adapter2 := NewTaurusNetworkAdapter(sid, "party2", network2, ids)
	adapter3 := NewTaurusNetworkAdapter(sid, "party3", network3, ids)

	party1 := NewCmpParty(sid, "party1", ids, 2, pl, adapter1)
	party2 := NewCmpParty(sid, "party2", ids, 2, pl, adapter2)
	party3 := NewCmpParty(sid, "party3", ids, 2, pl, adapter3)

	result1 := make(chan types.KeyData, 1)
	result2 := make(chan types.KeyData, 1)
	result3 := make(chan types.KeyData, 1)

	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		defer wg.Done()
		res, err := party1.Keygen(context.Background())
		if err != nil {
			t.Errorf("party1 keygen error: %v", err)
			return
		}
		result1 <- res
	}()

	go func() {
		defer wg.Done()
		res, err := party2.Keygen(context.Background())
		if err != nil {
			t.Errorf("party2 keygen error: %v", err)
			return
		}
		result2 <- res
	}()

	go func() {
		defer wg.Done()
		res, err := party3.Keygen(context.Background())
		if err != nil {
			t.Errorf("party3 keygen error: %v", err)
			return
		}
		result3 <- res
	}()

	wg.Wait()

	// Read the actual values from channels
	r1 := <-result1
	r2 := <-result2
	r3 := <-result3

	fmt.Println("party1 result:", len(r1.Payload))
	fmt.Println("party2 result:", len(r2.Payload))
	fmt.Println("party3 result:", len(r3.Payload))
}
