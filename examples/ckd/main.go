package main

import (
	"fmt"
	"os"
	"os/signal"
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

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		KeyPath:  "./event_initiator.key",
	})

	// 2) Once wallet exists, immediately fire a SignTransaction
	txID := uuid.New().String()
	dummyTx := []byte("deadbeef") // replace with real transaction bytes

	txMsg := &types.SignTxMessage{
		KeyType:             types.KeyTypeSecp256k1, // now only supports ECDSA
		WalletID:            "739c2f58-8385-4c40-a642-9a8a1e0d336f",
		NetworkInternalCode: "sepolia-testnet",
		TxID:                txID,
		Tx:                  dummyTx,
		DerivationPath:      []uint32{1, 2, 3},
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
