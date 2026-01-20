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
	"strconv"
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
// --- Shared helpers (used by the Cardano PoC binaries) ---

type bfUtxo struct {
	TxHash  string `json:"tx_hash"`
	TxIndex int    `json:"tx_index"`
	Amount  []struct {
		Unit     string `json:"unit"`
		Quantity string `json:"quantity"`
	} `json:"amount"`
}

type simpleUtxo struct {
	TxHash       string
	TxIndex      uint32
	Lovelace     uint64
	LovelaceOnly bool // PoC flag: true if UTxO contains ONLY lovelace
	Assets       map[string]uint64 // unit => quantity; unit is "lovelace" or policy+asset hex
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

func assetUnitFromPolicyAndName(policyHex, nameHex string) (string, error) {
	policyHex = strings.TrimPrefix(policyHex, "0x")
	nameHex = strings.TrimPrefix(nameHex, "0x")
	if len(policyHex) != 56 {
		return "", fmt.Errorf("policy_id_hex must be 56 hex chars, got %d", len(policyHex))
	}
	if _, err := hex.DecodeString(policyHex); err != nil {
		return "", fmt.Errorf("invalid policy_id_hex: %w", err)
	}
	if nameHex != "" {
		if _, err := hex.DecodeString(nameHex); err != nil {
			return "", fmt.Errorf("invalid asset_name_hex: %w", err)
		}
	}
	return policyHex + nameHex, nil
}

func sumAssetsMaps(dst map[string]uint64, src map[string]uint64) {
	for unit, q := range src {
		dst[unit] += q
	}
}

func subAssetsMaps(dst map[string]uint64, src map[string]uint64) error {
	for unit, q := range src {
		cur := dst[unit]
		if cur < q {
			return fmt.Errorf("insufficient asset %s: have %d need %d", unit, cur, q)
		}
		if cur == q {
			delete(dst, unit)
		} else {
			dst[unit] = cur - q
		}
	}
	return nil
}

func assetsMapToCardanoAssets(m map[string]uint64) ([]cardanoAsset, error) {
	out := make([]cardanoAsset, 0)
	for unit, q := range m {
		if unit == "lovelace" {
			continue
		}
		if q == 0 {
			continue
		}
		if len(unit) < 56 {
			return nil, fmt.Errorf("invalid asset unit (too short): %s", unit)
		}
		policy := unit[:56]
		name := unit[56:]
		out = append(out, cardanoAsset{PolicyIDHex: policy, AssetNameHex: name, Quantity: q})
	}
	return out, nil
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
	MinFeeA          int    `json:"min_fee_a"`
	MinFeeB          int    `json:"min_fee_b"`
	CoinsPerUTXOWord string `json:"coins_per_utxo_word"` // Blockfrost returns this as a string
	Epoch            int    `json:"epoch"`
	Slot             int    `json:"slot"`
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
// --- Cardano multi-asset (token) helpers for the PoC ---

// cardanoAmount represents an amount in a tx output.
// - For ADA-only: uint64 lovelace
// - For multi-asset: [lovelace, {policyIdBytes: {assetNameBytes: quantity}}]
// CBOR map keys must be raw bytes (policy id 28 bytes, asset name 0..32 bytes).
// This is a simplified model sufficient for common native assets.

type cardanoAsset struct {
	PolicyIDHex    string // 56 hex chars => 28 bytes
	AssetNameHex   string // hex-encoded asset name bytes (can be empty)
	Quantity       uint64
}

func buildTxBodyCBORMultiAsset(
	inputs []txInput,
	toAddr string,
	toLovelace uint64,
	toAssets []cardanoAsset,
	changeAddr string,
	changeLovelace uint64,
	changeAssets []cardanoAsset,
	feeLovelace uint64,
	ttlSlot uint64,
) ([]byte, error) {
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

	mkAmount := func(lovelace uint64, assets []cardanoAsset) (any, error) {
		if len(assets) == 0 {
			return lovelace, nil
		}

		// IMPORTANT:
		// - Go map keys cannot be slices ([]byte)
		// - Cardano multi-asset CBOR requires keys to be byte strings (policy_id bytes, asset_name bytes)
		// We use hex strings as intermediate keys, then build a CBOR-ready structure
		// using cbor.ByteString as map keys (hashable), avoiding "unhashable []uint8" panics.
		policies := make(map[string]map[string]uint64)

		for _, a := range assets {
			if a.Quantity == 0 {
				continue
			}
			policyHex := strings.TrimPrefix(a.PolicyIDHex, "0x")
			assetHex := strings.TrimPrefix(a.AssetNameHex, "0x")

			if len(policyHex) != 56 {
				return nil, fmt.Errorf("policy_id_hex must be 56 hex chars (28 bytes), got %d", len(policyHex))
			}
			if _, err := hex.DecodeString(policyHex); err != nil {
				return nil, fmt.Errorf("invalid policy_id_hex: %w", err)
			}
			if assetHex != "" {
				if _, err := hex.DecodeString(assetHex); err != nil {
					return nil, fmt.Errorf("invalid asset_name_hex: %w", err)
				}
			}

			inner, ok := policies[policyHex]
			if !ok {
				inner = make(map[string]uint64)
				policies[policyHex] = inner
			}
			inner[assetHex] += a.Quantity
		}

		cborPolicies := make(map[any]any)
		for policyHex, assetsByName := range policies {
			pidBytes, _ := hex.DecodeString(policyHex)
			cborInner := make(map[any]any)
			for assetHex, qty := range assetsByName {
				nameBytes := []byte{}
				if assetHex != "" {
					nameBytes, _ = hex.DecodeString(assetHex)
				}
				cborInner[cbor.ByteString(nameBytes)] = qty
			}
			cborPolicies[cbor.ByteString(pidBytes)] = cborInner
		}

		return []any{lovelace, cborPolicies}, nil
	}

	toAmt, err := mkAmount(toLovelace, toAssets)
	if err != nil {
		return nil, err
	}
	out1 := []any{toBytes, toAmt}
	outs := []any{out1}
	if changeLovelace > 0 || len(changeAssets) > 0 {
		chgAmt, err := mkAmount(changeLovelace, changeAssets)
		if err != nil {
			return nil, err
		}
		out2 := []any{chgBytes, chgAmt}
		outs = append(outs, out2)
	}

	body := map[any]any{0: cborInputs, 1: outs, 2: feeLovelace}
	if ttlSlot > 0 {
		body[uint64(3)] = ttlSlot
	}
	return cbor.Marshal(body)
}



func estimateMinAdaForOutput(params *protocolParams, addrBech32 string, lovelace uint64, assets []cardanoAsset) (uint64, error) {
	const (
		fallback        uint64 = 2_000_000
		minAdaWithToken uint64 = 1_200_000 // Minimum 1.2 ADA is a safe bet for outputs with native tokens.
	)

	if len(assets) > 0 {
		// If the output includes any native tokens, enforce the minimum ADA requirement for such outputs.
		return minAdaWithToken, nil
	}

	// The rest of this function is for ADA-only outputs, which have a lower min-ADA requirement.
	coinsPerUTXOWord := 0
	if params != nil {
		coinsPerUTXOWord, _ = strconv.Atoi(strings.TrimSpace(params.CoinsPerUTXOWord))
	}
	if coinsPerUTXOWord == 0 {
		return fallback, nil
	}

	addrBytes, err := decodeCardanoAddressBytes(addrBech32)
	if err != nil {
		return fallback, nil
	}

	output := []any{addrBytes, lovelace}
	ser, err := cbor.Marshal(output)
	if err != nil {
		return fallback, nil
	}

	minAda := (160 + uint64(len(ser))) * uint64(coinsPerUTXOWord) / 8
	if minAda == 0 {
		return fallback, nil
	}
	return minAda, nil
}

func parseCardanoAssetArg(s string) (cardanoAsset, error) {
    var out cardanoAsset
    s = strings.TrimSpace(s)
    if s == "" {
        return out, errors.New("empty asset spec")
    }

    parts := strings.Split(s, ":")
    if len(parts) != 2 {
        return out, fmt.Errorf("invalid asset spec (missing ':'): %s", s)
    }

    idPart := strings.TrimSpace(parts[0])
    qtyPart := strings.TrimSpace(parts[1])

    var qtyF float64
    if _, err := fmt.Sscanf(qtyPart, "%f", &qtyF); err != nil {
        return out, fmt.Errorf("invalid quantity: %w", err)
    }
    qty := uint64(qtyF * 1_000_000)

    policy := idPart
    var assetName string

    if strings.Contains(idPart, ".") {
        sp := strings.SplitN(idPart, ".", 2)
        policy = sp[0]
        assetName = sp[1]
        
        // Convert ASCII asset names to hex (Blockfrost uses hex-encoded asset names).
        if assetName != "" && !isHex(assetName) {
            assetName = hex.EncodeToString([]byte(assetName))
        }
    }

    out.PolicyIDHex = policy
    out.AssetNameHex = assetName
    out.Quantity = qty

    return out, nil
}

// isHex reports whether s contains only hexadecimal characters.
func isHex(s string) bool {
    for _, c := range s {
        if !((c >= '0' && c <= '9') || 
             (c >= 'a' && c <= 'f') || 
             (c >= 'A' && c <= 'F')) {
            return false
        }
    }
    return len(s) > 0
}

func parseAmountToAssetsMap(amount []struct {
	Unit     string `json:"unit"`
	Quantity string `json:"quantity"`
}) (map[string]uint64, error) {
	assets := make(map[string]uint64)
	for _, a := range amount {
		qty, err := strconv.ParseUint(a.Quantity, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid quantity for asset %s: %v", a.Unit, err)
		}
		assets[a.Unit] = qty
	}
	return assets, nil
}