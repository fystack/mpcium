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
	"strings"
	"time"

	"github.com/cosmos/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/viper"
	"golang.org/x/crypto/blake2b"
)

type bfConfig struct {
	ProjectID    string
	BaseURL      string // e.g. https://cardano-preprod.blockfrost.io/api/v0
	Network      string // preprod|preview
	TTLSeconds   uint64
	MinChangeLov uint64
}

func loadBFConfig() bfConfig {
	cfg := bfConfig{}
	cfg.ProjectID = viper.GetString("blockfrost_project_id")
	cfg.Network = viper.GetString("network")
	if cfg.Network == "" {
		cfg.Network = "preprod"
	}
	cfg.BaseURL = viper.GetString("blockfrost_base_url")
	if cfg.BaseURL == "" {
		switch strings.ToLower(cfg.Network) {
		case "preview":
			cfg.BaseURL = "https://cardano-preview.blockfrost.io/api/v0"
		default:
			cfg.BaseURL = "https://cardano-preprod.blockfrost.io/api/v0"
		}
	}
	cfg.TTLSeconds = uint64(viper.GetInt("ttl_seconds"))
	if cfg.TTLSeconds == 0 {
		cfg.TTLSeconds = 3600
	}
	cfg.MinChangeLov = uint64(viper.GetInt("min_change_lovelace"))
	if cfg.MinChangeLov == 0 {
		cfg.MinChangeLov = 1_000_000
	}
	return cfg
}
// --- shared helpers (used by create_wallet.go and sign_tx.go) ---

type bfUtxo struct {
	TxHash  string `json:"tx_hash"`
	TxIndex int    `json:"tx_index"`
	Amount  []struct {
		Unit     string `json:"unit"`
		Quantity string `json:"quantity"`
	} `json:"amount"`
}

type simpleUtxo struct {
	TxHash      string
	TxIndex     uint32
	Lovelace    uint64
	LovelaceOnly bool // PoC flag: true if UTxO contains ONLY lovelace
}

func normalizeEd25519PubKey(pk []byte) ([]byte, error) {
	if len(pk) == 32 {
		return pk, nil
	}
	if len(pk) == 33 && (pk[0] == 0x02 || pk[0] == 0x03) {
		return pk[1:], nil
	}
	prefix := byte(0)
	if len(pk) > 0 {
		prefix = pk[0]
	}
	return nil, fmt.Errorf("unsupported eddsa pubkey format: len=%d prefix=0x%02x", len(pk), prefix)
}

func deriveEnterpriseAddressPreprod(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
		return "", fmt.Errorf("expected 32-byte ed25519 pubkey, got %d", len(pubKey))
	}
	h, err := blake2b.New(28, nil)
	if err != nil {
		return "", err
	}
	_, _ = h.Write(pubKey)
	payKeyHash := h.Sum(nil)

	header := byte(0x60) // enterprise, network id 0 (preprod/testnet)
	addrBytes := append([]byte{header}, payKeyHash...)

	data5, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		return "", err
	}
	encoded, err := bech32.Encode("addr_test", data5)
	if err != nil {
		return "", err
	}
	// sanity
	_, decoded5, derr := bech32.DecodeNoLimit(encoded)
	if derr != nil {
		return "", fmt.Errorf("bech32 self-check decode failed: %w", derr)
	}
	decoded8, derr := bech32.ConvertBits(decoded5, 5, 8, false)
	if derr != nil {
		return "", fmt.Errorf("bech32 self-check convertbits failed: %w", derr)
	}
	if !bytes.Equal(decoded8, addrBytes) {
		return "", fmt.Errorf("bech32 self-check mismatch")
	}
	return encoded, nil
}

func decodeCardanoAddressBytes(addrStr string) ([]byte, error) {
	_, data5, err := bech32.DecodeNoLimit(addrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32 address '%s': %w", addrStr, err)
	}
	data8, err := bech32.ConvertBits(data5, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert address bits for '%s': %w", addrStr, err)
	}
	return data8, nil
}

type txInput struct {
	TxHashHex string
	TxIndex   uint32
}

func buildTxBodyCBOR(inputs []txInput, toAddr string, toLovelace uint64, changeAddr string, changeLovelace uint64, feeLovelace uint64, ttlSlot uint64) ([]byte, error) {
	toBytes, err := decodeCardanoAddressBytes(toAddr)
	if err != nil {
		return nil, err
	}
	chgBytes, err := decodeCardanoAddressBytes(changeAddr)
	if err != nil {
		return nil, err
	}

	cborInputs := make([]any, 0, len(inputs))
	for _, in := range inputs {
		txHash, err := hex.DecodeString(in.TxHashHex)
		if err != nil {
			return nil, err
		}
		if len(txHash) != 32 {
			return nil, fmt.Errorf("tx hash must be 32 bytes, got %d", len(txHash))
		}
		cborInputs = append(cborInputs, []any{txHash, in.TxIndex})
	}

	out1 := []any{toBytes, toLovelace}
	outs := []any{out1}
	if changeLovelace > 0 {
		out2 := []any{chgBytes, changeLovelace}
		outs = append(outs, out2)
	}
	body := map[any]any{0: cborInputs, 1: outs, 2: feeLovelace}
	if ttlSlot > 0 {
		// 3 = ttl/invalid_hereafter
		body[uint64(3)] = ttlSlot
	}
	return cbor.Marshal(body)
}
func blockfrostGETWithRetry(ctx context.Context, projectID, url string) ([]byte, int, error) {
	// Simple PoC retry for 429/5xx
	var lastErr error
	for i := 0; i < 4; i++ {
		b, status, err := blockfrostGET(ctx, projectID, url)
		if err == nil && status >= 200 && status < 300 {
			return b, status, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d: %s", status, prettyJSON(b))
			// no retry for 4xx except 429
			if status >= 400 && status < 500 && status != 429 {
				return b, status, lastErr
			}
		}
		time.Sleep(time.Duration(250*(i+1)) * time.Millisecond)
	}
	return nil, 0, lastErr
}

func blockfrostPOSTCBORWithRetry(ctx context.Context, projectID, url string, cborBody []byte) ([]byte, int, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		b, status, err := blockfrostPOSTCBOR(ctx, projectID, url, cborBody)
		if err == nil && status >= 200 && status < 300 {
			return b, status, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d: %s", status, prettyJSON(b))
			if status >= 400 && status < 500 && status != 429 {
				return b, status, lastErr
			}
		}
		time.Sleep(time.Duration(300*(i+1)) * time.Millisecond)
	}
	return nil, 0, lastErr
}

func buildSignedTxCBOR(txBodyCbor []byte, pubKey []byte, sig []byte) ([]byte, error) {
	if len(sig) == 0 {
		return nil, errors.New("empty signature")
	}
	witnessSet := map[any]any{0: []any{[]any{pubKey, sig}}}
	var body any
	if err := cbor.Unmarshal(txBodyCbor, &body); err != nil {
		return nil, err
	}
	tx := []any{body, witnessSet, true, nil}
	return cbor.Marshal(tx)
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

func blockfrostPOSTCBOR(ctx context.Context, projectID, url string, cborBytes []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(cborBytes))
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

func prettyJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

func trimJSONQuotes(s string) string {
	s = strings.TrimSpace(s)
	return strings.Trim(s, "\"\n\r\t ")
}

type protocolParams struct {
	MinFeeA    int `json:"min_fee_a"`
	MinFeeB    int `json:"min_fee_b"`
	Epoch      int `json:"epoch"`
	Slot       int `json:"slot"`
}

func fetchProtocolParams(ctx context.Context, cfg bfConfig) (*protocolParams, error) {
	url := cfg.BaseURL + "/epochs/latest/parameters"
	b, status, err := blockfrostGET(ctx, cfg.ProjectID, url)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("protocol params HTTP %d: %s", status, prettyJSON(b))
	}

	var params protocolParams
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}
	return &params, nil
}
// fetchCurrentSlot returns the latest known slot number from Blockfrost.
func fetchCurrentSlot(ctx context.Context, cfg bfConfig) (uint64, error) {
	url := cfg.BaseURL + "/blocks/latest"
	b, status, err := blockfrostGET(ctx, cfg.ProjectID, url)
	if err != nil {
		return 0, err
	}
	if status < 200 || status >= 300 {
		return 0, fmt.Errorf("blocks/latest HTTP %d: %s", status, prettyJSON(b))
	}
	var resp struct {
		Slot uint64 `json:"slot"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return 0, err
	}
	if resp.Slot == 0 {
		return 0, errors.New("blockfrost returned slot=0")
	}
	return resp.Slot, nil
}