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
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	const environment = "development"
	config.InitViperConfig()
	logger.Init(environment, false)

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain() // drain inflight msgs
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		KeyPath:  "./event_initiator.key",
	})
	err = mpcClient.OnResharingResult(func(event event.ResharingSuccessEvent) {
		logger.Info("Received resharing result", "event", event)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to resharing results", err)
	}

	walletID := "892122fd-f2f4-46dc-be25-6fd0b83dff60"
	if err := mpcClient.Resharing(walletID, 2, types.KeyTypeSecp256k1); err != nil {
		logger.Fatal("Resharing failed", err)
	}
	logger.Info("Resharing sent, awaiting result...", "walletID", walletID)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
