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

	// 3) Listen for signing results
	err = mpcClient.OnResharingResult(func(evt event.ResharingResultEvent) {
		logger.Info("Resharing result received",
			"walletID", evt.WalletID,
			"pubKey", fmt.Sprintf("%x", evt.PubKey),
			"newThreshold", evt.NewThreshold,
			"keyType", evt.KeyType,
		)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to OnResharingResult", err)
	}

	resharingMsg := &types.ResharingMessage{
		SessionID: uuid.NewString(),
		WalletID:  "506d2d40-483a-49f1-93c8-27dd4fe9740c",
		NodeIDs: []string{
			"c95c340e-5a18-472d-b9b0-5ac68218213a",
			"ac37e85f-caca-4bee-8a3a-49a0fe35abff",
		}, // new peer IDs

		NewThreshold: 1, // t+1 <= len(NodeIDs)
		KeyType:      types.KeyTypeEd25519,
		Protocol:     types.ProtocolFROST,
	}
	err = mpcClient.Resharing(resharingMsg)
	if err != nil {
		logger.Fatal("Resharing failed", err)
	}
	fmt.Printf("Resharing(%q) sent, awaiting result...\n", resharingMsg.WalletID)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
