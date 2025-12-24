//go:build sign_tx

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

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
//   $env:BLOCKFROST_PROJECT_ID="..."
//   go run ./examples/cardano_poc/sign_tx.go --wallet-id <uuid> --to <addr_test...> --amount-ada 1
//
// Notes:
// - This file does NOT wait for UTxO. It expects you to fund the deposit address first.
// - It reads pubkey from examples/cardano_poc/cardano_poc_wallet.json.

type walletFile struct {
	WalletID       string `json:"wallet_id"`
	EDDSAPubKeyHex string `json:"eddsa_pubkey_hex"`
}

func main() {
	logger.Init("development", true)
	config.InitViperConfig("")

	bfProjectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	if bfProjectID == "" {
		logger.Fatal("BLOCKFROST_PROJECT_ID env var is required", nil)
	}

	walletID := ""
	toAddr := ""
	amountAda := uint64(1)
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--wallet-id":
			i++
			walletID = os.Args[i]
		case "--to":
			i++
			toAddr = os.Args[i]
		case "--amount-ada":
			i++
			_, _ = fmt.Sscanf(os.Args[i], "%d", &amountAda)
		}
	}
	if walletID == "" || toAddr == "" {
		logger.Fatal("usage: sign_tx.go --wallet-id <uuid> --to <addr_test...> --amount-ada 1", nil)
	}

	b, err := os.ReadFile("examples/cardano_poc/cardano_poc_wallet.json")
	if err != nil {
		logger.Fatal("failed to read wallet file", err)
	}
	var wf walletFile
	if err := json.Unmarshal(b, &wf); err != nil {
		logger.Fatal("invalid wallet file json", err)
	}
	if wf.WalletID != walletID {
		logger.Fatal(fmt.Sprintf("wallet mismatch: file has %s", wf.WalletID), nil)
	}
	pubKeyBytes, err := hex.DecodeString(wf.EDDSAPubKeyHex)
	if err != nil {
		logger.Fatal("invalid pubkey hex", err)
	}

	rawPub, err := normalizeEd25519PubKey(pubKeyBytes)
	if err != nil {
		logger.Fatal("normalize pubkey failed", err)
	}
	ourAddr, err := deriveEnterpriseAddressPreprod(rawPub)
	if err != nil {
		logger.Fatal("derive address failed", err)
	}
	logger.Info("Deposit address (must be funded before signing)", "address", ourAddr)

	// Fetch first UTxO once (NO WAIT/RETRY)
	utxo, err := fetchFirstUtxoOnce(context.Background(), bfProjectID, ourAddr)
	if err != nil {
		logger.Fatal("fetch utxo failed", err)
	}
	logger.Info("Using UTxO", "tx_hash", utxo.TxHash, "tx_index", utxo.TxIndex, "lovelace", utxo.Lovelace)

	sendLovelace := amountAda * 1_000_000
	feeLovelace := uint64(200_000)
	if utxo.Lovelace <= sendLovelace+feeLovelace {
		logger.Fatal("not enough funds", nil)
	}
	change := utxo.Lovelace - sendLovelace - feeLovelace

	txBodyCbor, err := buildTxBodyCBOR(utxo.TxHash, utxo.TxIndex, toAddr, sendLovelace, ourAddr, change, feeLovelace)
	if err != nil {
		logger.Fatal("buildTxBodyCBOR failed", err)
	}
	h := blake2b.Sum256(txBodyCbor)
	txHash := h[:]
	logger.Info("Prepared tx hash", "tx_hash_hex", hex.EncodeToString(txHash))

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

	signResultCh := make(chan event.SigningResultEvent, 1)
	err = mpcClient.OnSignResult(func(evt event.SigningResultEvent) {
		if evt.WalletID == walletID {
			signResultCh <- evt
		}
	})
	if err != nil {
		logger.Fatal("OnSignResult subscribe failed", err)
	}

	txID := uuid.New().String()
	if err := mpcClient.SignTransaction(&types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            walletID,
		NetworkInternalCode: "cardano-testnet",
		TxID:                txID,
		Tx:                  txHash,
	}); err != nil {
		logger.Fatal("SignTransaction failed", err)
	}
	logger.Info("SignTransaction sent", "txID", txID)

	select {
	case res := <-signResultCh:
		if res.ResultType == event.ResultTypeError {
			logger.Fatal("Signing failed: "+res.ErrorReason, nil)
		}

		signedTxCbor, err := buildSignedTxCBOR(txBodyCbor, rawPub, res.Signature)
		if err != nil {
			logger.Fatal("buildSignedTxCBOR failed", err)
		}

		submitURL := "https://cardano-preprod.blockfrost.io/api/v0/tx/submit"
		respBody, status, err := blockfrostPOSTCBOR(context.Background(), bfProjectID, submitURL, signedTxCbor)
		if err != nil {
			logger.Fatal("submit failed", err)
		}
		if status < 200 || status >= 300 {
			logger.Fatal(fmt.Sprintf("submit HTTP %d: %s", status, prettyJSON(respBody)), nil)
		}
		var submittedHash string
		_ = json.Unmarshal(respBody, &submittedHash)
		if submittedHash == "" {
			submittedHash = strings.TrimSpace(string(respBody))
		}
		fmt.Println(submittedHash)
		logger.Info("Submitted tx", "tx_hash", submittedHash)
	case <-time.After(60 * time.Second):
		logger.Fatal("Timeout waiting for signing result", errors.New("timeout"))
	}
}

func fetchFirstUtxoOnce(ctx context.Context, projectID, addr string) (*simpleUtxo, error) {
	url := "https://cardano-preprod.blockfrost.io/api/v0/addresses/" + addr + "/utxos"
	b, status, err := blockfrostGET(ctx, projectID, url)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, errors.New("address not found on-chain yet (404) - fund it first")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("utxo HTTP %d: %s", status, prettyJSON(b))
	}
	var utxos []bfUtxo
	if err := json.Unmarshal(b, &utxos); err != nil {
		return nil, err
	}
	if len(utxos) == 0 {
		return nil, errors.New("no UTxO at address - fund it first")
	}
	lovelace, err := findLovelace(utxos[0].Amount)
	if err != nil {
		return nil, err
	}
	return &simpleUtxo{TxHash: utxos[0].TxHash, TxIndex: uint32(utxos[0].TxIndex), Lovelace: lovelace}, nil
}
