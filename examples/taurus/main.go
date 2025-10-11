package main

import (
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

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
	config.InitViperConfig("")
	logger.Init(environment, true)

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}

	// Validate algorithm
	if !slices.Contains(
		[]string{
			string(types.EventInitiatorKeyTypeEd25519),
			string(types.EventInitiatorKeyTypeP256),
		},
		algorithm,
	) {
		logger.Fatal(
			fmt.Sprintf(
				"invalid algorithm: %s. Must be %s or %s",
				algorithm,
				types.EventInitiatorKeyTypeEd25519,
				types.EventInitiatorKeyTypeP256,
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

	localSigner, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{
		KeyPath: "./event_initiator.key",
	})
	if err != nil {
		logger.Fatal("Failed to create local signer", err)
	}

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		Signer:   localSigner,
	})

	// Generate a new wallet ID for this demo
	walletID := uuid.New().String()
	fmt.Printf("Generated wallet ID: %s\n", walletID)

	// Step 1: Key Generation
	fmt.Println("Step 1: Generating Taurus CMP keys...")

	err = mpcClient.OnWalletCreationResult(func(evt event.KeygenResultEvent) {
		if evt.ResultType == event.ResultTypeSuccess {
			logger.Info("Taurus CMP key generation completed successfully",
				"walletID", evt.WalletID,
				"taurusPubKeySize", len(evt.TaurusCMPPubKey),
			)
			fmt.Printf("Taurus CMP key generated successfully\n")
			fmt.Printf("   Public key size: %d bytes\n", len(evt.TaurusCMPPubKey))
		} else {
			logger.Error("Taurus CMP key generation failed", nil,
				"walletID", evt.WalletID,
				"error", evt.ErrorReason,
			)
			fmt.Printf("Taurus CMP key generation failed: %s\n", evt.ErrorReason)
		}
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to wallet creation results", err)
	}

	err = mpcClient.CreateWallet(walletID)
	if err != nil {
		logger.Fatal("Failed to create wallet", err)
	}

	fmt.Printf("Wallet creation request sent for %s\n", walletID)
	fmt.Println("Waiting for key generation to complete...")
	fmt.Println("Note: This generates keys for all protocols (ECDSA, EdDSA, Taurus CMP)")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("\nShutting down Taurus CMP demo.")
}
