//go:build create_wallet

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
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

// Usage:
//   go run ./examples/cardano_poc/create_wallet.go
// Output:
//   Prints wallet_id and deposit address (enterprise) to stdout.
//
// Note: this command does NOT wait for funding.

func main() {
	const environment = "development"
	config.InitViperConfig("examples/cardano_poc/config.yaml")
	logger.Init(environment, true)

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	if !slices.Contains([]string{string(types.EventInitiatorKeyTypeEd25519), string(types.EventInitiatorKeyTypeP256)}, algorithm) {
		logger.Fatal(fmt.Sprintf("invalid algorithm: %s", algorithm), nil)
	}

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	localSigner, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{KeyPath: "./event_initiator.key"})
	if err != nil {
		logger.Fatal("Failed to create local signer", err)
	}

	mpcClient := client.NewMPCClient(client.Options{NatsConn: natsConn, Signer: localSigner})

	walletID := uuid.New().String()
	created := make(chan event.KeygenResultEvent, 1)
	err = mpcClient.OnWalletCreationResult(func(evt event.KeygenResultEvent) {
		if evt.WalletID == walletID {
			created <- evt
		}
	})
	if err != nil {
		logger.Fatal("OnWalletCreationResult subscribe failed", err)
	}

	if err := mpcClient.CreateWallet(walletID); err != nil {
		logger.Fatal("CreateWallet failed", err)
	}
	logger.Info("CreateWallet sent", "walletID", walletID)

	select {
	case keygen := <-created:
		if keygen.ResultType == event.ResultTypeError {
			logger.Fatal("Keygen failed: "+keygen.ErrorReason, nil)
		}

		rawPub, err := normalizeEd25519PubKey(keygen.EDDSAPubKey)
		if err != nil {
			logger.Fatal("normalize pubkey failed", err)
		}
		ourAddr, err := deriveEnterpriseAddressPreprod(rawPub)
		if err != nil {
			logger.Fatal("derive address failed", err)
		}

		// Read existing wallets, add the new one, and write back.
		const walletFilePath = "examples/cardano_poc/cardano_poc_wallet.json"
		type walletRecord struct {
			WalletID       string `json:"wallet_id"`
			EDDSAPubKeyHex string `json:"eddsa_pubkey_hex"`
			DepositAddress string `json:"deposit_address"`
		}

		wallets := make(map[string]walletRecord)
		b, err := os.ReadFile(walletFilePath)
		if err == nil { // if file exists and is readable
			if jerr := json.Unmarshal(b, &wallets); jerr != nil {
				logger.Fatal("failed to unmarshal existing wallet file", jerr)
			}
		} else if !os.IsNotExist(err) { // if error is something other than "not found"
			logger.Fatal("failed to read wallet file", err)
		}

		// Add new wallet
		wallets[walletID] = walletRecord{
			WalletID:       walletID,
			EDDSAPubKeyHex: hex.EncodeToString(keygen.EDDSAPubKey),
			DepositAddress: ourAddr,
		}

		// Write back to file
		recBytes, err := json.MarshalIndent(wallets, "", "  ")
		if err != nil {
			logger.Fatal("failed to marshal wallet file json", err)
		}
		if werr := os.WriteFile(walletFilePath, recBytes, 0o644); werr != nil {
			logger.Fatal("failed to write wallet file", werr)
		}

		fmt.Println("wallet_id:", walletID)
		fmt.Println("eddsa_pubkey_hex:", hex.EncodeToString(keygen.EDDSAPubKey))
		fmt.Println("deposit_address:", ourAddr)
	case <-time.After(60 * time.Second):
		logger.Fatal("Timeout waiting for wallet creation", errors.New("timeout"))
	}
}
