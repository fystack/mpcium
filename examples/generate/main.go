package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
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

func main() {
	const environment = "development"
	numWallets := flag.Int("n", 1, "Number of wallets to generate")

	flag.Parse()

	config.InitViperConfig()
	logger.Init(environment, false)

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.KeyTypeEd25519)
	}

	if !slices.Contains(
		[]string{string(types.KeyTypeEd25519), string(types.KeyTypeP256)},
		algorithm,
	) {
		logger.Fatal(
			fmt.Sprintf(
				"invalid algorithm: %s. Must be %s or %s",
				algorithm,
				types.KeyTypeEd25519,
				types.KeyTypeP256,
			),
			nil,
		)
	}

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		Algorithm: algorithm,
		NatsConn:  natsConn,
		KeyPath:   "./event_initiator.key",
	})

	var walletStartTimes sync.Map
	var walletIDs []string
	var walletIDsMu sync.Mutex
	var wg sync.WaitGroup
	var completedCount int32

	startAll := time.Now()

	// STEP 1: Pre-generate wallet IDs and store start times
	for i := 0; i < *numWallets; i++ {
		walletID := uuid.New().String()
		walletStartTimes.Store(walletID, time.Now())

		walletIDsMu.Lock()
		walletIDs = append(walletIDs, walletID)
		walletIDsMu.Unlock()
	}

	// STEP 2: Register the result handler AFTER all walletIDs are stored
	err = mpcClient.OnWalletCreationResult(func(event event.KeygenResultEvent) {
		logger.Info("Received wallet creation result", "event", event)
		now := time.Now()
		startTimeAny, ok := walletStartTimes.Load(event.WalletID)
		if ok {
			startTime := startTimeAny.(time.Time)
			duration := now.Sub(startTime).Seconds()
			accumulated := now.Sub(startAll).Seconds()
			countSoFar := atomic.AddInt32(&completedCount, 1)

			logger.Info("Wallet created",
				"walletID", event.WalletID,
				"duration_seconds", fmt.Sprintf("%.3f", duration),
				"accumulated_time_seconds", fmt.Sprintf("%.3f", accumulated),
				"count_so_far", countSoFar,
			)

			walletStartTimes.Delete(event.WalletID)
		} else {
			logger.Warn("Received wallet result but no start time found", "walletID", event.WalletID)
		}
		wg.Done()
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to wallet-creation results", err)
	}

	// STEP 3: Create wallets
	for _, walletID := range walletIDs {
		wg.Add(1) // Add to WaitGroup BEFORE attempting to create wallet

		if err := mpcClient.CreateWallet(walletID); err != nil {
			logger.Error("CreateWallet failed", err)
			walletStartTimes.Delete(walletID)
			wg.Done() // Now this is safe since we added 1 above
			continue
		}

		logger.Info("CreateWallet sent, awaiting result...", "walletID", walletID)
	}

	// Wait until all wallet creations complete
	go func() {
		wg.Wait()
		totalDuration := time.Since(startAll).Seconds()
		logger.Info(
			"All wallets generated",
			"count",
			completedCount,
			"total_duration_seconds",
			fmt.Sprintf("%.3f", totalDuration),
		)

		// Save wallet IDs to wallets.json
		walletIDsMu.Lock()
		data, err := json.MarshalIndent(walletIDs, "", "  ")
		walletIDsMu.Unlock()
		if err != nil {
			logger.Error("Failed to marshal wallet IDs", err)
		} else {
			err = os.WriteFile("wallets.json", data, 0600)
			if err != nil {
				logger.Error("Failed to write wallets.json", err)
			} else {
				logger.Info("wallets.json written", "count", len(walletIDs))
			}
		}
		os.Exit(0)
	}()

	// Block on SIGINT/SIGTERM (Ctrl+C etc.)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
