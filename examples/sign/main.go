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
	const environment = "dev"
	config.InitViperConfig()
	logger.Init(environment, true)

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.KeyTypeEd25519)
	}

	// Validate algorithm
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

	// 2) Once wallet exists, immediately fire a SignTransaction
	txID := uuid.New().String()
	dummyTx := []byte("deadbeef") // replace with real transaction bytes

	// Determine key type based on algorithm
	var keyType types.KeyType
	switch algorithm {
	case string(types.KeyTypeEd25519):
		keyType = types.KeyTypeEd25519
	case string(types.KeyTypeP256):
		keyType = types.KeyTypeP256
	default:
		logger.Fatal("Unsupported algorithm", nil)
	}

	txMsg := &types.SignTxMessage{
		KeyType:             keyType,
		WalletID:            "ad24f678-b04b-4149-bcf6-bf9c90df8e63", // Use the generated wallet ID
		NetworkInternalCode: "solana-devnet",
		TxID:                txID,
		Tx:                  dummyTx,
	}
	err = mpcClient.SignTransaction(txMsg)
	if err != nil {
		logger.Fatal("SignTransaction failed", err)
	}
	fmt.Printf("SignTransaction(%q) sent, awaiting result...\n", txID)

	// 3) Listen for signing results
	err = mpcClient.OnSignResult(func(evt event.SigningResultEvent) {
		logger.Info("Signing result received",
			"txID", evt.TxID,
			"signature", fmt.Sprintf("%x", evt.Signature),
		)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to OnSignResult", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
