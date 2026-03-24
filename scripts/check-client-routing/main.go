package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

type clientStats struct {
	name      string
	clientID  string
	requested map[string]struct{}
	received  map[string]event.KeygenResultEvent
	misrouted map[string]event.KeygenResultEvent
	untracked map[string]event.KeygenResultEvent
}

type routingState struct {
	mu           sync.Mutex
	clients      map[string]*clientStats
	totalWanted  int
	totalResults int
	doneCh       chan struct{}
	doneOnce     sync.Once
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "client routing check failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	clientAID := flag.String("client-a-id", "svc-a", "Client ID for client A")
	clientBID := flag.String("client-b-id", "svc-b", "Client ID for client B")
	keyPath := flag.String("key-path", "./event_initiator.key", "Path to the event initiator private key")
	natsURLFlag := flag.String("nats-url", "", "NATS URL override (defaults to config nats.url)")
	algorithmFlag := flag.String("algorithm", "", "Initiator signing algorithm override (ed25519 or p256)")
	walletsPerClient := flag.Int("wallets-per-client", 3, "Number of wallet creation requests per client")
	timeout := flag.Duration("timeout", 90*time.Second, "Max time to wait for all results")
	listenerWarmup := flag.Duration("listener-warmup", 3*time.Second, "Delay after listener setup before sending requests")
	legacyMode := flag.Bool("legacy", false, "Create both clients without client IDs to reproduce the old shared-queue behavior")
	flag.Parse()

	if *walletsPerClient <= 0 {
		return fmt.Errorf("wallets-per-client must be > 0")
	}

	config.InitViperConfig("")
	logger.Init("dev", true)

	algorithm := *algorithmFlag
	if algorithm == "" {
		algorithm = viper.GetString("event_initiator_algorithm")
	}
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	if !slices.Contains(
		[]string{
			string(types.EventInitiatorKeyTypeEd25519),
			string(types.EventInitiatorKeyTypeP256),
		},
		algorithm,
	) {
		return fmt.Errorf(
			"invalid algorithm %q: must be %s or %s",
			algorithm,
			types.EventInitiatorKeyTypeEd25519,
			types.EventInitiatorKeyTypeP256,
		)
	}

	natsURL := *natsURLFlag
	if natsURL == "" {
		natsURL = viper.GetString("nats.url")
	}
	if natsURL == "" {
		return fmt.Errorf("nats url is required")
	}

	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	signer, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{
		KeyPath: *keyPath,
	})
	if err != nil {
		return fmt.Errorf("create local signer: %w", err)
	}

	clientA := newMPCClient(natsConn, signer, *clientAID, *legacyMode)
	clientB := newMPCClient(natsConn, signer, *clientBID, *legacyMode)

	effectiveClientAID := *clientAID
	effectiveClientBID := *clientBID
	if *legacyMode {
		effectiveClientAID = ""
		effectiveClientBID = ""
	}

	state := &routingState{
		clients: map[string]*clientStats{
			"A": {
				name:      "A",
				clientID:  effectiveClientAID,
				requested: make(map[string]struct{}),
				received:  make(map[string]event.KeygenResultEvent),
				misrouted: make(map[string]event.KeygenResultEvent),
				untracked: make(map[string]event.KeygenResultEvent),
			},
			"B": {
				name:      "B",
				clientID:  effectiveClientBID,
				requested: make(map[string]struct{}),
				received:  make(map[string]event.KeygenResultEvent),
				misrouted: make(map[string]event.KeygenResultEvent),
				untracked: make(map[string]event.KeygenResultEvent),
			},
		},
		totalWanted: *walletsPerClient * 2,
		doneCh:      make(chan struct{}),
	}

	if err := clientA.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		state.record("A", result)
	}); err != nil {
		return fmt.Errorf("subscribe client A: %w", err)
	}
	if err := clientB.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		state.record("B", result)
	}); err != nil {
		return fmt.Errorf("subscribe client B: %w", err)
	}

	fmt.Printf("listeners ready, waiting %s before publishing requests\n", listenerWarmup.String())
	time.Sleep(*listenerWarmup)

	requestsA := make([]string, 0, *walletsPerClient)
	requestsB := make([]string, 0, *walletsPerClient)

	for i := 0; i < *walletsPerClient; i++ {
		walletID := "route-a-" + uuid.NewString()
		state.clients["A"].requested[walletID] = struct{}{}
		requestsA = append(requestsA, walletID)
	}
	for i := 0; i < *walletsPerClient; i++ {
		walletID := "route-b-" + uuid.NewString()
		state.clients["B"].requested[walletID] = struct{}{}
		requestsB = append(requestsB, walletID)
	}

	fmt.Printf("mode=%s clientA=%q clientB=%q wallets-per-client=%d\n",
		modeName(*legacyMode), effectiveClientAID, effectiveClientBID, *walletsPerClient)
	fmt.Printf("client A requested wallets: %v\n", requestsA)
	fmt.Printf("client B requested wallets: %v\n", requestsB)

	var publishWG sync.WaitGroup
	publishWG.Add(2)
	go func() {
		defer publishWG.Done()
		for _, walletID := range requestsA {
			if err := clientA.CreateWallet(walletID); err != nil {
				logger.Error("Client A create wallet failed", err, "walletID", walletID)
			}
		}
	}()
	go func() {
		defer publishWG.Done()
		for _, walletID := range requestsB {
			if err := clientB.CreateWallet(walletID); err != nil {
				logger.Error("Client B create wallet failed", err, "walletID", walletID)
			}
		}
	}()
	publishWG.Wait()

	select {
	case <-state.doneCh:
	case <-time.After(*timeout):
		fmt.Printf("timed out after %s waiting for results\n", timeout.String())
	}

	printSummary(state)

	if err := state.validate(); err != nil {
		return err
	}

	fmt.Println("routing check passed: no client received another client's result")
	return nil
}

func newMPCClient(natsConn *nats.Conn, signer client.Signer, clientID string, legacy bool) client.MPCClient {
	opts := client.Options{
		NatsConn: natsConn,
		Signer:   signer,
	}
	if legacy {
		return client.NewMPCClient(opts)
	}
	return client.NewMPCClient(opts, client.WithClientID(clientID))
}

func (s *routingState) record(clientName string, result event.KeygenResultEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := s.clients[clientName]
	if _, exists := stats.received[result.WalletID]; exists {
		return
	}

	stats.received[result.WalletID] = result
	s.totalResults++

	if _, ok := stats.requested[result.WalletID]; ok {
		if s.totalResults >= s.totalWanted {
			s.doneOnce.Do(func() {
				close(s.doneCh)
			})
		}
		return
	}

	if otherName := otherClientName(clientName); otherName != "" {
		if _, ok := s.clients[otherName].requested[result.WalletID]; ok {
			stats.misrouted[result.WalletID] = result
		} else {
			stats.untracked[result.WalletID] = result
		}
	}

	if s.totalResults >= s.totalWanted {
		s.doneOnce.Do(func() {
			close(s.doneCh)
		})
	}
}

func (s *routingState) validate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var reasons []string
	for _, name := range []string{"A", "B"} {
		stats := s.clients[name]
		if len(stats.misrouted) > 0 {
			reasons = append(reasons, fmt.Sprintf("client %s received %d misrouted result(s)", name, len(stats.misrouted)))
		}
		if len(stats.untracked) > 0 {
			reasons = append(reasons, fmt.Sprintf("client %s received %d unexpected result(s)", name, len(stats.untracked)))
		}
		if missing := missingWallets(stats); len(missing) > 0 {
			reasons = append(reasons, fmt.Sprintf("client %s is missing %d expected result(s): %v", name, len(missing), missing))
		}
	}

	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%v", reasons)
}

func printSummary(state *routingState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	fmt.Println("---- routing summary ----")
	for _, name := range []string{"A", "B"} {
		stats := state.clients[name]
		fmt.Printf("client %s (clientID=%q): requested=%d received=%d misrouted=%d unexpected=%d missing=%d\n",
			stats.name,
			stats.clientID,
			len(stats.requested),
			len(stats.received),
			len(stats.misrouted),
			len(stats.untracked),
			len(missingWallets(stats)),
		)
		if len(stats.misrouted) > 0 {
			fmt.Printf("  misrouted wallets: %v\n", sortedEventKeys(stats.misrouted))
		}
		if len(stats.untracked) > 0 {
			fmt.Printf("  unexpected wallets: %v\n", sortedEventKeys(stats.untracked))
		}
		if missing := missingWallets(stats); len(missing) > 0 {
			fmt.Printf("  missing wallets: %v\n", missing)
		}
	}
	fmt.Println("-------------------------")
}

func missingWallets(stats *clientStats) []string {
	missing := make([]string, 0)
	for walletID := range stats.requested {
		if _, ok := stats.received[walletID]; !ok {
			missing = append(missing, walletID)
		}
	}
	slices.Sort(missing)
	return missing
}

func sortedEventKeys(events map[string]event.KeygenResultEvent) []string {
	keys := make([]string, 0, len(events))
	for walletID := range events {
		keys = append(keys, walletID)
	}
	slices.Sort(keys)
	return keys
}

func otherClientName(name string) string {
	switch name {
	case "A":
		return "B"
	case "B":
		return "A"
	default:
		return ""
	}
}

func modeName(legacy bool) string {
	if legacy {
		return "legacy"
	}
	return "scoped"
}
