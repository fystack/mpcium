package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/cosmos/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

// Minimal Cardano preprod PoC:
// - CreateWallet (MPCIUM) -> EDDSA pubkey
// - Derive enterprise address
// - Wait for funding UTxO (Blockfrost)
// - Build tx body CBOR, ask MPCIUM to sign tx-body hash
// - Build signed tx CBOR and submit (Blockfrost)

func main() {
	const environment = "development"
	config.InitViperConfig("")
	logger.Init(environment, true)

	bfProjectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	if bfProjectID == "" {
		logger.Fatal("BLOCKFROST_PROJECT_ID env var is required", nil)
	}

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

	var keygen event.KeygenResultEvent
	select {
	case keygen = <-created:
		if keygen.ResultType == event.ResultTypeError {
			logger.Fatal("Keygen failed: "+keygen.ErrorReason, nil)
		}
		logger.Info("Wallet created", "walletID", keygen.WalletID, "eddsa_pubkey_hex", hex.EncodeToString(keygen.EDDSAPubKey))
	case <-time.After(60 * time.Second):
		logger.Fatal("Timeout waiting for wallet creation", nil)
	}

	// 2) Normalize EDDSA pubkey (MPCIUM may return 33-byte compressed; Cardano needs 32-byte raw)
	rawPub, err := normalizeEd25519PubKey(keygen.EDDSAPubKey)
	if err != nil {
		logger.Fatal("normalize pubkey failed", err)
	}
	logger.Info("EDDSA pubkey length", "len", len(keygen.EDDSAPubKey), "raw_len", len(rawPub))

	// 3) Derive Cardano preprod enterprise address from pubkey
	ourAddr, err := deriveEnterpriseAddressPreprod(rawPub)
	if err != nil {
		logger.Fatal("derive address failed", err)
	}
	logger.Info("Derived deposit address", "address", ourAddr)

	// 3) Wait for funds then fetch UTxOs (Blockfrost)
	// Many explorers show an address even before it has appeared on-chain,
	// but Blockfrost returns 404 until the first tx/UTxO exists for that address.
	// So we poll with a generous timeout.
	const depositWaitTimeout = 15 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), depositWaitTimeout)
	defer cancel()
	utxo, err := waitForFirstUtxo(ctx, bfProjectID, ourAddr)
	if err != nil {
		logger.Fatal("waiting utxo failed", err)
	}
	logger.Info("Found UTxO", "tx_hash", utxo.TxHash, "tx_index", utxo.TxIndex, "lovelace", utxo.Lovelace)

	// 4) Build a minimal tx body (1 input -> 1 output to destination + change back)
	destAddr := "addr_test1qqe4rw4jujaezsrux4f4u58tyxl7ffr0aj7t8fnxukc702utg7lxfcdeet9d0kk73jlmuwytv6aj5t96mazuh7lpv8kq2ekx5u"
	sendLovelace := uint64(1_000_000) // 1 ADA
	feeLovelace := uint64(200_000)    // rough fee for PoC
	change := utxo.Lovelace - sendLovelace - feeLovelace
	if utxo.Lovelace <= sendLovelace+feeLovelace {
		logger.Fatal("not enough funds in UTxO", nil)
	}

	txBodyCbor, err := buildTxBodyCBOR(utxo.TxHash, utxo.TxIndex, destAddr, sendLovelace, ourAddr, change, feeLovelace)
	if err != nil {
		logger.Fatal("buildTxBodyCBOR failed", err)
	}

	// 5) Hash tx body (Cardano rule) and sign with MPCIUM
	h := blake2b.Sum256(txBodyCbor)
	txHash := h[:]
	logger.Info("Prepared tx hash", "tx_hash_hex", hex.EncodeToString(txHash))

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
	signMsg := &types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            walletID,
		NetworkInternalCode: "cardano-testnet",
		TxID:                txID,
		Tx:                  txHash, // IMPORTANT: we ask MPCIUM to sign txHash bytes
	}
	if err := mpcClient.SignTransaction(signMsg); err != nil {
		logger.Fatal("SignTransaction failed", err)
	}
	logger.Info("SignTransaction sent", "txID", txID)

	select {
	case res := <-signResultCh:
		if res.ResultType == event.ResultTypeError {
			logger.Fatal("Signing failed: "+res.ErrorReason, nil)
		}
		logger.Info("Signature received", "sig_hex", hex.EncodeToString(res.Signature))

		// 6) Build witness + full tx and submit via Blockfrost
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
		_ = json.Unmarshal(respBody, &submittedHash) // response is a JSON string
		if submittedHash == "" {
			submittedHash = strings.TrimSpace(string(respBody))
		}
		logger.Info("Submitted tx", "tx_hash", submittedHash)
	case <-time.After(60 * time.Second):
		logger.Fatal("Timeout waiting for signing result", nil)
	}

}

// --- Cardano helpers (preprod) ---

func normalizeEd25519PubKey(pk []byte) ([]byte, error) {
	// Cardano Ed25519 vkey is 32 bytes.
	if len(pk) == 32 {
		return pk, nil
	}
	// MPCIUM EDDSA pubkey is sometimes encoded as 33 bytes with 0x02/0x03 prefix.
	if len(pk) == 33 && (pk[0] == 0x02 || pk[0] == 0x03) {
		return pk[1:], nil
	}
	prefix := byte(0)
	if len(pk) > 0 {
		prefix = pk[0]
	}
	return nil, fmt.Errorf("unsupported eddsa pubkey format: len=%d prefix=0x%02x", len(pk), prefix)
}

type bfUtxo struct {
	TxHash  string `json:"tx_hash"`
	TxIndex int    `json:"tx_index"`
	Amount  []struct {
		Unit     string `json:"unit"`
		Quantity string `json:"quantity"`
	} `json:"amount"`
}

type simpleUtxo struct {
	TxHash   string
	TxIndex  uint32
	Lovelace uint64
}

func waitForFirstUtxo(ctx context.Context, projectID, addr string) (*simpleUtxo, error) {
	url := "https://cardano-preprod.blockfrost.io/api/v0/addresses/" + addr + "/utxos"
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			b, status, err := blockfrostGET(ctx, projectID, url)
			if err != nil {
				return nil, err
			}
			if status == 404 {
				logger.Info("UTxO not found yet (404), waiting...", "address", addr)
				continue
			}
			if status < 200 || status >= 300 {
				return nil, fmt.Errorf("utxo HTTP %d: %s", status, prettyJSON(b))
			}
			var utxos []bfUtxo
			if err := json.Unmarshal(b, &utxos); err != nil {
				return nil, err
			}
			if len(utxos) == 0 {
				logger.Info("No UTxO yet, waiting...", "address", addr)
				continue
			}
			lovelace, err := findLovelace(utxos[0].Amount)
			if err != nil {
				return nil, err
			}
			return &simpleUtxo{TxHash: utxos[0].TxHash, TxIndex: uint32(utxos[0].TxIndex), Lovelace: lovelace}, nil
		}
	}
}

func findLovelace(amts []struct {
	Unit     string `json:"unit"`
	Quantity string `json:"quantity"`
}) (uint64, error) {
	for _, a := range amts {
		if a.Unit == "lovelace" {
			var v uint64
			_, err := fmt.Sscanf(a.Quantity, "%d", &v)
			return v, err
		}
	}
	return 0, errors.New("no lovelace in utxo")
}

func deriveEnterpriseAddressPreprod(pubKey []byte) (string, error) {
	// Cardano enterprise address (CIP-19) for testnet/preprod.
	// address = header || payment_keyhash
	// header: 0b0110 (enterprise) << 4 | network_id
	// preprod network_id = 0 (same as testnet)
	if len(pubKey) != 32 {
		return "", fmt.Errorf("expected 32-byte ed25519 pubkey, got %d", len(pubKey))
	}

	// payment key hash = blake2b-224(pubkey)
	// (matches cardano-serialization-lib: utxoPubKey.to_raw_key().hash())
	h, err := blake2b.New(28, nil)
	if err != nil {
		return "", err
	}
	_, _ = h.Write(pubKey)
	payKeyHash := h.Sum(nil) // 28 bytes

	// preprod/testnet network id = 0
	header := byte(0x60) // enterprise (0x6) with network id 0
	addrBytes := append([]byte{header}, payKeyHash...)

	data5, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		return "", err
	}
	encoded, err := bech32.Encode("addr_test", data5)
	if err != nil {
		return "", err
	}

	// sanity check: decode back the bytes we just encoded
	_, decoded5, derr := bech32.DecodeNoLimit(encoded)
	if derr != nil {
		return "", fmt.Errorf("bech32 self-check decode failed: %w", derr)
	}
	decoded8, derr := bech32.ConvertBits(decoded5, 5, 8, false)
	if derr != nil {
		return "", fmt.Errorf("bech32 self-check convertbits failed: %w", derr)
	}
	if !bytes.Equal(decoded8, addrBytes) {
		return "", fmt.Errorf("bech32 self-check mismatch: want %x got %x", addrBytes, decoded8)
	}

	return encoded, nil
}

// TxBody CBOR is a CBOR map keyed by integers per Cardano spec.
// For PoC we keep it minimal: inputs, outputs, fee.
func buildTxBodyCBOR(txHashHex string, txIndex uint32, toAddr string, toLovelace uint64, changeAddr string, changeLovelace uint64, feeLovelace uint64) ([]byte, error) {
	// Inputs: [ [ txHash(bytes32), index(uint) ] ]
	txHash, err := hex.DecodeString(txHashHex)
	if err != nil {
		return nil, err
	}
	if len(txHash) != 32 {
		return nil, fmt.Errorf("tx hash must be 32 bytes, got %d", len(txHash))
	}

	toBytes, err := decodeCardanoAddressBytes(toAddr)
	if err != nil {
		return nil, err
	}
	chgBytes, err := decodeCardanoAddressBytes(changeAddr)
	if err != nil {
		return nil, err
	}

	// Cardano TxOut value is a Coin (uint) for ADA-only, or a multi-asset structure.
	// For ADA-only outputs, encode value as uint (NOT a map).
	out1 := []any{toBytes, toLovelace}
	out2 := []any{chgBytes, changeLovelace}

	body := map[any]any{
		0: []any{[]any{txHash, txIndex}}, // inputs
		1: []any{out1, out2},             // outputs
		2: feeLovelace,                   // fee
	}
	return cbor.Marshal(body)
}
func decodeCardanoAddressBytes(addrStr string) ([]byte, error) {
	_, data5, err := bech32.DecodeNoLimit(addrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32 address '%s': %w", addrStr, err)
	}
	// The data part returned by Decode is 5-bit grouped. Convert to 8-bit bytes.
	data8, err := bech32.ConvertBits(data5, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert address bits for '%s': %w", addrStr, err)
	}
	return data8, nil
}

func buildSignedTxCBOR(txBodyCbor []byte, pubKey []byte, sig []byte) ([]byte, error) {
	if len(sig) == 0 {
		return nil, errors.New("empty signature")
	}
	// Transaction: [ tx_body, witness_set, is_valid(true), auxiliary_data(nil) ]
	// Witness set for vkey: { 0: [ [ vkey, sig ] ] }
	witnessSet := map[any]any{0: []any{[]any{pubKey, sig}}}

	var body any
	if err := cbor.Unmarshal(txBodyCbor, &body); err != nil {
		return nil, err
	}
	tx := []any{body, witnessSet, true, nil}
	return cbor.Marshal(tx)
}

// --- Blockfrost helpers ---

func blockfrostGET(ctx context.Context, projectID, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("project_id", projectID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

func blockfrostPOSTCBOR(ctx context.Context, projectID, url string, cbor []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(cbor))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("project_id", projectID)
	req.Header.Set("Content-Type", "application/cbor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

// Debug helper
func prettyJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}
