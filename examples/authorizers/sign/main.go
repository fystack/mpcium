package main

import (
	"encoding/hex"
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

// Required authorizer names (hardcoded as requested)
var requiredAuthorizers = []string{"authorizer1", "authorizer2"}

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

	// Load authorizer signers
	authorizerSigners := make(map[string]client.Signer)
	for _, authorizerID := range requiredAuthorizers {
		keyPath := fmt.Sprintf("./%s.authorizer.key", authorizerID)
		signer, err := client.NewLocalSigner(types.EventInitiatorKeyTypeEd25519, client.LocalSignerOptions{
			KeyPath: keyPath,
		})
		if err != nil {
			logger.Fatal(fmt.Sprintf("Failed to create authorizer signer for %s", authorizerID), err)
		}
		authorizerSigners[authorizerID] = signer
	}

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		Signer:   localSigner,
	})

	// Create a signing request with authorizers
	txID := uuid.New().String()
	dummyTx := []byte("deadbeef") // replace with real transaction bytes

	txMsg := &types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            "ad24f678-b04b-4149-bcf6-bf9c90df8e63", // Use the generated wallet ID
		NetworkInternalCode: "solana-devnet",
		TxID:                txID,
		Tx:                  dummyTx,
	}

	// First, we need to sign the message with the initiator to get the signature
	raw, err := txMsg.Raw()
	if err != nil {
		logger.Fatal("Failed to get raw message", err)
	}

	signature, err := localSigner.Sign(raw)
	if err != nil {
		logger.Fatal("Failed to sign message", err)
	}
	txMsg.Signature = signature

	// Collect authorizer signatures
	authorizerRaw, err := types.ComposeAuthorizerRaw(txMsg)
	if err != nil {
		logger.Fatal("Failed to compose authorizer raw data", err)
	}

	for _, authorizerID := range requiredAuthorizers {
		signer := authorizerSigners[authorizerID]
		authSig, err := signer.Sign(authorizerRaw)
		if err != nil {
			logger.Fatal(fmt.Sprintf("Failed to sign with authorizer %s", authorizerID), err)
		}

		txMsg.AuthorizerSignatures = append(txMsg.AuthorizerSignatures, types.AuthorizerSignature{
			AuthorizerID: authorizerID,
			Signature:    authSig,
		})

		logger.Info("Added authorizer signature",
			"authorizer", authorizerID,
			"signature", hex.EncodeToString(authSig),
		)
	}

	// Send the signing request with authorizer signatures
	err = mpcClient.SignTransaction(txMsg)
	if err != nil {
		logger.Fatal("SignTransaction failed", err)
	}
	logger.Info("SignTransaction sent with authorizers, awaiting result...",
		"txID", txID,
		"authorizers", requiredAuthorizers,
	)

	// Listen for signing results
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
