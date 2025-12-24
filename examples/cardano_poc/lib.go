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

	"github.com/cosmos/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

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
	TxHash   string
	TxIndex  uint32
	Lovelace uint64
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

func buildTxBodyCBOR(txHashHex string, txIndex uint32, toAddr string, toLovelace uint64, changeAddr string, changeLovelace uint64, feeLovelace uint64) ([]byte, error) {
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
	out1 := []any{toBytes, toLovelace}
	outs := []any{out1}
	if changeLovelace > 0 {
		out2 := []any{chgBytes, changeLovelace}
		outs = append(outs, out2)
	}
	body := map[any]any{0: []any{[]any{txHash, txIndex}}, 1: outs, 2: feeLovelace}
	return cbor.Marshal(body)
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
