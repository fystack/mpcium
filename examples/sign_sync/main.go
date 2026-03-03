package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	const environment = "dev"
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

	// 2) Once wallet exists, immediately fire a SignTransaction
	txID := uuid.New().String()
	dummyTx := []byte("deadbeef") // replace with real transaction bytes

	txMsg := &types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            "88f1512b-2508-4992-a076-5416fb0aae28", // Use the generated wallet ID
		NetworkInternalCode: "solana-devnet",
		TxID:                txID,
		Tx:                  dummyTx,
	}
	// 3) Use SignTransactionSync to get result directly
	ctx := context.Background()
	result, err := mpcClient.SignTransactionSync(ctx, txMsg)
	if err != nil {
		logger.Fatal("SignTransactionSync failed", err)
	}

	logger.Info("Signing result received",
		"txID", result.TxID,
		"signature", fmt.Sprintf("%x", result.Signature),
		"resultType", result.ResultType,
		"errorCode", result.ErrorCode,
		"errorReason", result.ErrorReason,
	)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
