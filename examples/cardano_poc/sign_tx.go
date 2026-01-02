//go:build sign_tx

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
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
//   go run -tags=sign_tx ./examples/cardano_poc --wallet-id <uuid> --to <addr_test...> --amount-ada <number ex: 1>
//
// Notes:
// - This binary does NOT wait for UTxO confirmation. Fund the deposit address first.
// - It reads pubkey/address from examples/cardano_poc/cardano_poc_wallet.json.
// - For sending native tokens, use sign_tx_token.

type walletRecord struct {
	WalletID       string `json:"wallet_id"`
	EDDSAPubKeyHex string `json:"eddsa_pubkey_hex"`
	DepositAddress string `json:"deposit_address"`
}



func main() {
	logger.Init("development", true)
	config.InitViperConfig("examples/cardano_poc/config.yaml")

	bfCfg := loadBFConfig()
	if bfCfg.ProjectID == "" {
		logger.Fatal("blockfrost_project_id is not set in examples/cardano_poc/config.yaml", nil)
	}

	params, err := fetchProtocolParams(context.Background(), bfCfg)
	if err != nil {
		logger.Fatal("failed to fetch protocol params", err)
	}
	logger.Info("Fetched protocol params", "min_fee_a", params.MinFeeA, "min_fee_b", params.MinFeeB, "network", bfCfg.Network, "base_url", bfCfg.BaseURL)

	walletID, toAddr, amountAda := parseArgsOrFatal()
	wf, rawPub, ourAddr := loadWalletOrFatal(walletID)
	logger.Info("Using wallet", "wallet_id", wf.WalletID, "address", ourAddr)

	minChangeLovelace := bfCfg.MinChangeLov
	sendLovelace := uint64(amountAda * 1_000_000)
	// Fail fast: ADA-only outputs must be >= min-UTxO. We use min_change_lovelace as PoC guard.
	if sendLovelace < minChangeLovelace {
		logger.Fatal(fmt.Sprintf("amount too small: send_lovelace=%d < min_change_lovelace=%d (increase --amount-ada)", sendLovelace, minChangeLovelace), nil)
	}

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
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
	if err := mpcClient.OnSignResult(func(evt event.SigningResultEvent) {
		if evt.WalletID == walletID {
			signResultCh <- evt
		}
	}); err != nil {
		logger.Fatal("OnSignResult subscribe failed", err)
	}

	submitURL := bfCfg.BaseURL + "/tx/submit"
	maxAttempts := 2
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		submittedHash, retryableErr, err := buildSignSubmitOnce(context.Background(), bfCfg, params, mpcClient, signResultCh, submitURL, walletID, rawPub, ourAddr, toAddr, sendLovelace, minChangeLovelace)
		if err != nil && strings.Contains(err.Error(), "no ADA-only UTxO") {
			// Fallback: the wallet may only have multi-asset UTxOs.
			// Build a multi-asset tx body that sends only ADA to the recipient,
			// while returning all non-ADA assets back to our change output.
			submittedHash, retryableErr, err = buildSignSubmitMultiAssetAdaFallback(context.Background(), bfCfg, params, mpcClient, signResultCh, submitURL, walletID, rawPub, ourAddr, toAddr, sendLovelace, minChangeLovelace)
		}
		if err == nil {
			fmt.Println(submittedHash)
			fmt.Println("explorer:", "https://preprod.cardanoscan.io/transaction/"+submittedHash)
			return
		}
		logger.Info("Submit attempt failed", "attempt", attempt, "retryable", retryableErr, "error", err.Error())
		if !retryableErr || attempt == maxAttempts {
			logger.Fatal("submit failed", err)
		}
		logger.Info("Rebuilding tx after failure", "next_attempt", attempt+1)
	}
}

func parseArgsOrFatal() (walletID string, toAddr string, amountAda float64) {
	amountAda = 1.0
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
			_, _ = fmt.Sscanf(os.Args[i], "%f", &amountAda)
		}
	}
	if walletID == "" || toAddr == "" {
		logger.Fatal(`Invalid arguments. Usage:
  --wallet-id <uuid>      Wallet ID from cardano_poc_wallet.json
  --to <addr_test...>     Recipient address
  --amount-ada <number>   ADA amount to send`, nil)
	}
	return
}

func loadWalletOrFatal(walletID string) (walletRecord, []byte, string) {
	const walletFilePath = "examples/cardano_poc/cardano_poc_wallet.json"
	b, err := os.ReadFile(walletFilePath)
	if err != nil {
		logger.Fatal("failed to read wallet file", err)
	}
	wallets := make(map[string]walletRecord)
	if err := json.Unmarshal(b, &wallets); err != nil {
		logger.Fatal("failed to unmarshal wallets file", err)
	}
	wf, ok := wallets[walletID]
	if !ok {
		logger.Fatal(fmt.Sprintf("wallet with ID %s not found in %s", walletID, walletFilePath), nil)
	}
	pubKeyBytes, err := hex.DecodeString(wf.EDDSAPubKeyHex)
	if err != nil {
		logger.Fatal("invalid pubkey hex", err)
	}
	rawPub, err := normalizeEd25519PubKey(pubKeyBytes)
	if err != nil {
		logger.Fatal("normalize pubkey failed", err)
	}
	return wf, rawPub, wf.DepositAddress
}

func buildSignSubmitOnce(
	ctx context.Context,
	bfCfg bfConfig,
	params *protocolParams,
	mpcClient client.MPCClient,
	signResultCh <-chan event.SigningResultEvent,
	submitURL string,
	walletID string,
	rawPub []byte,
	ourAddr string,
	toAddr string,
	sendLovelace uint64,
	minChangeLovelace uint64,
) (submittedHash string, retryable bool, err error) {
	// 1) Fetch UTxOs
	utxos, err := fetchAllUtxosOnce(ctx, bfCfg, ourAddr)
	if err != nil {
		return "", true, err
	}
	if len(utxos) == 0 {
		return "", false, errors.New("no UTxO at address")
	}
	// For ADA-only send, we must NOT spend UTxOs that also carry tokens.
	// If we do, we'd need to reproduce those tokens in outputs; otherwise ValueNotConservedUTxO.
	filtered := make([]simpleUtxo, 0, len(utxos))
	for _, u := range utxos {
		if u.LovelaceOnly {
			filtered = append(filtered, u)
		}
	}
	if len(filtered) == 0 {
		return "", false, errors.New("no ADA-only UTxO at address")
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Lovelace > filtered[j].Lovelace })

	// 2) TTL
	currentSlot, err := fetchCurrentSlot(ctx, bfCfg)
	if err != nil {
		return "", true, err
	}
	ttlSlot := currentSlot + bfCfg.TTLSeconds
	logger.Info("Using TTL", "current_slot", currentSlot, "ttl_slot", ttlSlot)

	// 3) Coin selection (simple)
	const feeUpperBound uint64 = 600_000
	target := sendLovelace + feeUpperBound + minChangeLovelace
	var total uint64
	inputs := make([]txInput, 0, len(filtered))
	for _, u := range filtered {
		total += u.Lovelace
		inputs = append(inputs, txInput{TxHashHex: u.TxHash, TxIndex: u.TxIndex})
		if total >= target {
			break
		}
	}
	logger.Info("Selected UTxOs", "selected", len(inputs), "total_lovelace", total, "target_lovelace", target)
	if total < sendLovelace+minChangeLovelace {
		return "", false, errors.New("not enough funds")
	}

	// 4) Fee converge with dummy witness
	dummySig := make([]byte, 64)
	var feeLovelace uint64
	var change uint64
	var txBodyCbor []byte
	for iter := 0; iter < 3; iter++ {
		if total <= sendLovelace+feeLovelace {
			return "", false, errors.New("not enough funds after fee")
		}
		change = total - sendLovelace - feeLovelace
		if change > 0 && change < minChangeLovelace {
			// omit change output by folding into fee
			feeLovelace += change
			change = 0
		}
		body, err := buildTxBodyCBOR(inputs, toAddr, sendLovelace, ourAddr, change, feeLovelace, ttlSlot)
		if err != nil {
			return "", false, err
		}
		dummySigned, err := buildSignedTxCBOR(body, rawPub, dummySig)
		if err != nil {
			return "", false, err
		}
		size := len(dummySigned)
		newFee := uint64(params.MinFeeA*size + params.MinFeeB)
		logger.Info("Calculated fee", "iter", iter, "fee_lovelace", newFee, "signed_tx_size_bytes", size)
		if newFee == feeLovelace {
			txBodyCbor = body
			break
		}
		feeLovelace = newFee
		txBodyCbor = body
	}
	if txBodyCbor == nil {
		return "", false, errors.New("failed to build tx body")
	}

	// 5) Tx hash
	h := blake2b.Sum256(txBodyCbor)
	txHash := h[:]
	logger.Info("Prepared tx hash", "tx_hash_hex", hex.EncodeToString(txHash))

	// 6) Sign
	txID := uuid.New().String()
	if err := mpcClient.SignTransaction(&types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            walletID,
		NetworkInternalCode: "cardano-testnet",
		TxID:                txID,
		Tx:                  txHash,
	}); err != nil {
		return "", true, err
	}
	logger.Info("SignTransaction sent", "txID", txID)

	var res event.SigningResultEvent
	select {
	case res = <-signResultCh:
		if res.ResultType == event.ResultTypeError {
			return "", false, errors.New("signing failed: "+res.ErrorReason)
		}
	case <-time.After(60 * time.Second):
		return "", true, errors.New("timeout waiting for signing result")
	}

	// 7) Submit
	signedTxCbor, err := buildSignedTxCBOR(txBodyCbor, rawPub, res.Signature)
	if err != nil {
		return "", false, err
	}
	respBody, status, err := blockfrostPOSTCBORWithRetry(ctx, bfCfg.ProjectID, submitURL, signedTxCbor)
	if err != nil {
		return "", true, err
	}
	if status < 200 || status >= 300 {
		msg := prettyJSON(respBody)
		retryable = strings.Contains(msg, "BadInputsUTxO") || strings.Contains(msg, "InvalidWitnessesUTXOW") || strings.Contains(msg, "ValueNotConservedUTxO") || strings.Contains(msg, "OutsideValidityIntervalUTxO")
		return "", retryable, fmt.Errorf("submit HTTP %d: %s", status, msg)
	}
	_ = json.Unmarshal(respBody, &submittedHash)
	if submittedHash == "" {
		submittedHash = strings.TrimSpace(string(respBody))
	}
	return submittedHash, false, nil
}
// buildSignSubmitMultiAssetAdaFallback builds an ADA-send tx but allows selecting multi-asset UTxOs.
// Any non-lovelace assets present in the selected inputs are returned back to ourAddr as change,
// so ValueNotConservedUTxO is satisfied.
func buildSignSubmitMultiAssetAdaFallback(
	ctx context.Context,
	bfCfg bfConfig,
	params *protocolParams,
	mpcClient client.MPCClient,
	signResultCh <-chan event.SigningResultEvent,
	submitURL string,
	walletID string,
	rawPub []byte,
	ourAddr string,
	toAddr string,
	sendLovelace uint64,
	minChangeLovelace uint64,
) (submittedHash string, retryable bool, err error) {
	utxos, err := fetchAllUtxosOnce(ctx, bfCfg, ourAddr)
	if err != nil {
		return "", true, err
	}
	if len(utxos) == 0 {
		return "", false, errors.New("no UTxO at address")
	}

	currentSlot, err := fetchCurrentSlot(ctx, bfCfg)
	if err != nil {
		return "", true, err
	}
	ttlSlot := currentSlot + bfCfg.TTLSeconds
	logger.Info("Using TTL", "current_slot", currentSlot, "ttl_slot", ttlSlot)

	// coin selection over total lovelace (can include token-carrying utxos)
	const feeUpperBound uint64 = 900_000
	target := sendLovelace + feeUpperBound + minChangeLovelace
	sort.Slice(utxos, func(i, j int) bool { return utxos[i].Lovelace > utxos[j].Lovelace })

	inputs := make([]txInput, 0)
	totalInputAssets := make(map[string]uint64)
	for _, u := range utxos {
		inputs = append(inputs, txInput{TxHashHex: u.TxHash, TxIndex: u.TxIndex})
		sumAssetsMaps(totalInputAssets, u.Assets)
		if totalInputAssets["lovelace"] >= target {
			break
		}
	}
	logger.Info("Selected UTxOs (fallback)", "selected", len(inputs), "total_lovelace", totalInputAssets["lovelace"], "target_lovelace", target)
	if totalInputAssets["lovelace"] < sendLovelace+minChangeLovelace {
		return "", false, errors.New("not enough funds")
	}

	// outputs: receiver gets only lovelace; all other assets go back to change
	outputAssets := map[string]uint64{"lovelace": sendLovelace}

	dummySig := make([]byte, 64)
	var feeLovelace uint64
	var txBodyCbor []byte

	for iter := 0; iter < 3; iter++ {
		changeAssets := make(map[string]uint64)
		sumAssetsMaps(changeAssets, totalInputAssets)

		if err := subAssetsMaps(changeAssets, outputAssets); err != nil {
			return "", false, fmt.Errorf("value conservation error (outputs): %w", err)
		}
		if changeAssets["lovelace"] < feeLovelace {
			return "", false, errors.New("not enough lovelace for fee")
		}
		changeAssets["lovelace"] -= feeLovelace

		// dust change handling
		if changeAssets["lovelace"] > 0 && changeAssets["lovelace"] < minChangeLovelace {
			feeLovelace += changeAssets["lovelace"]
			changeAssets["lovelace"] = 0
		}
		if changeAssets["lovelace"] == 0 {
			delete(changeAssets, "lovelace")
		}

		changeAssetsSlice, err := assetsMapToCardanoAssets(changeAssets)
		if err != nil {
			return "", false, fmt.Errorf("failed to convert change map to slice: %w", err)
		}

		body, err := buildTxBodyCBORMultiAsset(
			inputs,
			toAddr, sendLovelace, nil,
			ourAddr, changeAssets["lovelace"], changeAssetsSlice,
			feeLovelace,
			ttlSlot,
		)
		if err != nil {
			return "", false, err
		}
		dummySigned, err := buildSignedTxCBOR(body, rawPub, dummySig)
		if err != nil {
			return "", false, err
		}
		size := len(dummySigned)
		newFee := uint64(params.MinFeeA*size + params.MinFeeB)
		logger.Info("Calculated fee", "iter", iter, "fee_lovelace", newFee, "signed_tx_size_bytes", size)
		if newFee == feeLovelace {
			txBodyCbor = body
			break
		}
		feeLovelace = newFee
		txBodyCbor = body
	}
	if txBodyCbor == nil {
		return "", false, errors.New("failed to build tx body")
	}

	h := blake2b.Sum256(txBodyCbor)
	txHash := h[:]
	logger.Info("Prepared tx hash", "tx_hash_hex", hex.EncodeToString(txHash))

	txID := uuid.New().String()
	if err := mpcClient.SignTransaction(&types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            walletID,
		NetworkInternalCode: "cardano-testnet",
		TxID:                txID,
		Tx:                  txHash,
	}); err != nil {
		return "", true, err
	}
	logger.Info("SignTransaction sent", "txID", txID)

	var res event.SigningResultEvent
	select {
	case res = <-signResultCh:
		if res.ResultType == event.ResultTypeError {
			return "", false, errors.New("signing failed: " + res.ErrorReason)
		}
	case <-time.After(60 * time.Second):
		return "", true, errors.New("timeout waiting for signing result")
	}

	signedTxCbor, err := buildSignedTxCBOR(txBodyCbor, rawPub, res.Signature)
	if err != nil {
		return "", false, err
	}
	respBody, status, err := blockfrostPOSTCBORWithRetry(ctx, bfCfg.ProjectID, submitURL, signedTxCbor)
	if err != nil {
		return "", true, err
	}
	if status < 200 || status >= 300 {
		msg := prettyJSON(respBody)
		retryable = strings.Contains(msg, "BadInputsUTxO") || strings.Contains(msg, "InvalidWitnessesUTXOW") || strings.Contains(msg, "ValueNotConservedUTxO") || strings.Contains(msg, "OutsideValidityIntervalUTxO")
		return "", retryable, fmt.Errorf("submit HTTP %d: %s", status, msg)
	}
	_ = json.Unmarshal(respBody, &submittedHash)
	if submittedHash == "" {
		submittedHash = strings.TrimSpace(string(respBody))
	}
	return submittedHash, false, nil
}


func fetchAllUtxosOnce(ctx context.Context, cfg bfConfig, addr string) ([]simpleUtxo, error) {
	url := cfg.BaseURL + "/addresses/" + addr + "/utxos"
	b, status, err := blockfrostGETWithRetry(ctx, cfg.ProjectID, url)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, errors.New("address not found on-chain yet (404) - fund it first")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("utxo HTTP %d: %s", status, prettyJSON(b))
	}
	var raw []bfUtxo
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("no UTxO at address - fund it first")
	}

	out := make([]simpleUtxo, 0, len(raw))
	for _, u := range raw {
		lovelace, err := findLovelace(u.Amount)
		if err != nil {
			return nil, err
		}
		assets, err := parseAmountToAssetsMap(u.Amount)
		if err != nil {
			return nil, err
		}
		lovelaceOnly := len(u.Amount) == 1
		out = append(out, simpleUtxo{TxHash: u.TxHash, TxIndex: uint32(u.TxIndex), Lovelace: lovelace, LovelaceOnly: lovelaceOnly, Assets: assets})
	}
	return out, nil
}