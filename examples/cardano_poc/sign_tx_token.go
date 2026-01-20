//go:build sign_tx_token

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
//   go run -tags=sign_tx_token ./examples/cardano_poc --wallet-id <uuid> --to <addr_test...> --token <policyIdHex>.<assetNameHex>:<qty>

type tokenArgs struct {
	WalletID string
	ToAddr   string
	Ada      float64
	Asset    cardanoAsset
}

type walletRecord struct {
	WalletID       string `json:"wallet_id"`
	EDDSAPubKeyHex string `json:"eddsa_pubkey_hex"`
	DepositAddress string `json:"deposit_address"`
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

	args := parseTokenArgsOrFatal()
	_, rawPub, ourAddr := loadWalletOrFatal(args.WalletID)
	logger.Info("Using wallet", "wallet_id", args.WalletID, "address", ourAddr)

	minChangeLovelace := bfCfg.MinChangeLov

	// sendAdaLov starts from user input (could be 0) and may be auto-bumped later.
	sendAdaLov := uint64(args.Ada * 1_000_000)

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
		if evt.WalletID == args.WalletID {
			signResultCh <- evt
		}
	}); err != nil {
		logger.Fatal("OnSignResult subscribe failed", err)
	}

	submitURL := bfCfg.BaseURL + "/tx/submit"
	maxAttempts := 2
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		submittedHash, retryableErr, err := buildSignSubmitTokenOnce(
			context.Background(), bfCfg, params,
			mpcClient, signResultCh,
			submitURL,
			args.WalletID, rawPub,
			ourAddr, args.ToAddr,
			sendAdaLov, args.Asset,
			minChangeLovelace,
		)
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

func parseTokenArgsOrFatal() tokenArgs {
	var out tokenArgs
	out.Ada = 0 // Default to 0, will be auto-calculated

	var tokenSpec string
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--wallet-id":
			i++
			out.WalletID = os.Args[i]
		case "--to":
			i++
			out.ToAddr = os.Args[i]
		case "--token":
			i++
			tokenSpec = os.Args[i]
		case "--ada":
			i++
			_, _ = fmt.Sscanf(os.Args[i], "%f", &out.Ada)
		}
	}
	if out.WalletID == "" || out.ToAddr == "" || tokenSpec == "" {
		logger.Fatal("usage: sign_tx_token --wallet-id <uuid> --to <addr_test...> --token <policy.asset:qty> [--ada 1.0]", nil)
	}
	asset, err := parseCardanoAssetArg(tokenSpec)
	if err != nil {
		logger.Fatal("invalid --token", err)
	}
	out.Asset = asset
	return out
}

func buildSignSubmitTokenOnce(
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
	toAdaLovelace uint64,
	token cardanoAsset,
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

	// 2) TTL
	currentSlot, err := fetchCurrentSlot(ctx, bfCfg)
	if err != nil {
		return "", true, err
	}
	ttlSlot := currentSlot + bfCfg.TTLSeconds
	logger.Info("Using TTL", "current_slot", currentSlot, "ttl_slot", ttlSlot)

	// 3) Coin selection & min-ADA calculation (multi-asset)
	const feeUpperBound uint64 = 900_000
	tokenUnit, err := assetUnitFromPolicyAndName(token.PolicyIDHex, token.AssetNameHex)
	if err != nil {
		return "", false, fmt.Errorf("invalid token spec: %w", err)
	}

	// 4) Ensure receiver output has enough ADA (min-UTxO) BEFORE selecting ADA-only inputs
	// NOTE: --ada is optional; we treat it as a *minimum* (can be 0).
	minToAda, err := estimateMinAdaForOutput(params, toAddr, 0, []cardanoAsset{token})
	if err != nil || minToAda == 0 {
		// Fallback to minChangeLovelace if calculation fails
		minToAda = minChangeLovelace
	}
	if toAdaLovelace < minToAda {
		logger.Info("Auto-bumping receiver ADA to satisfy min-UTxO", "min_required", minToAda, "requested", toAdaLovelace)
		toAdaLovelace = minToAda
	}

	// Find UTxOs with the target token, and other UTxOs for ADA
	tokenUtxos := make([]simpleUtxo, 0)
	adaOnlyUtxos := make([]simpleUtxo, 0)
	for _, u := range utxos {
		if u.Assets[tokenUnit] > 0 {
			tokenUtxos = append(tokenUtxos, u)
		}
		// Any UTxO that does NOT contain the target token can be used to top up lovelace for fees/min-ADA,
		// not only "lovelace-only" ones. This fixes the case where the wallet has ADA but it's sitting in
		// UTxOs that also contain other tokens.
		if u.Assets[tokenUnit] == 0 {
			adaOnlyUtxos = append(adaOnlyUtxos, u)
		}
	}
	sort.Slice(tokenUtxos, func(i, j int) bool { return tokenUtxos[i].Assets[tokenUnit] > tokenUtxos[j].Assets[tokenUnit] })
	sort.Slice(adaOnlyUtxos, func(i, j int) bool { return adaOnlyUtxos[i].Lovelace > adaOnlyUtxos[j].Lovelace })

	// Select token inputs first
	inputs := make([]txInput, 0)
	totalInputAssets := make(map[string]uint64)
	for _, u := range tokenUtxos {
		if totalInputAssets[tokenUnit] >= token.Quantity {
			break // we have enough of the target token
		}
		inputs = append(inputs, txInput{TxHashHex: u.TxHash, TxIndex: u.TxIndex})
		sumAssetsMaps(totalInputAssets, u.Assets)
	}
	if totalInputAssets[tokenUnit] < token.Quantity {
		return "", false, fmt.Errorf("insufficient token balance for %s: have %d, need %d", tokenUnit, totalInputAssets[tokenUnit], token.Quantity)
	}

	// Add ADA-only UTxOs if needed for fee + receiver min-ADA + change min-ADA
	neededLovelace := toAdaLovelace + feeUpperBound + minChangeLovelace
	if totalInputAssets["lovelace"] < neededLovelace {
		for _, u := range adaOnlyUtxos {
			inputs = append(inputs, txInput{TxHashHex: u.TxHash, TxIndex: u.TxIndex})
			sumAssetsMaps(totalInputAssets, u.Assets)
			if totalInputAssets["lovelace"] >= neededLovelace {
				break
			}
		}
	}
	logger.Info(
		"Selected UTxOs",
		"count", len(inputs),
		"total_input_lovelace", totalInputAssets["lovelace"],
		"total_input_token", totalInputAssets[tokenUnit],
		"needed_lovelace_upper_bound", neededLovelace,
	)

	// 5) Fee & Change Calculation
	dummySig := make([]byte, 64)
	var feeLovelace uint64
	var txBodyCbor []byte

	outputAssets := map[string]uint64{
		"lovelace": toAdaLovelace,
		tokenUnit:  token.Quantity,
	}

	for iter := 0; iter < 3; iter++ {
		// Calculate change based on current fee estimate
		changeAssets := make(map[string]uint64)
		sumAssetsMaps(changeAssets, totalInputAssets)

		// Subtract outputs
		if err := subAssetsMaps(changeAssets, outputAssets); err != nil {
			return "", false, fmt.Errorf("value conservation error (outputs): %w", err)
		}

		// Subtract fee
		if changeAssets["lovelace"] < feeLovelace {
			return "", false, errors.New("not enough lovelace for fee")
		}
		changeAssets["lovelace"] -= feeLovelace

		// Handle dust change
		changeLovelace := changeAssets["lovelace"]
		if changeLovelace > 0 && changeLovelace < minChangeLovelace {
			feeLovelace += changeLovelace
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
			toAddr, toAdaLovelace, []cardanoAsset{token},
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

