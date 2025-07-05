package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyTypeConstants(t *testing.T) {
	assert.Equal(t, "secp256k1", string(KeyTypeSecp256k1))
	assert.Equal(t, "ed25519", string(KeyTypeEd25519))
}

func TestGenerateKeyMessage_Raw(t *testing.T) {
	msg := &GenerateKeyMessage{
		WalletID:  "test-wallet-123",
		Signature: []byte("test-signature"),
	}

	raw, err := msg.Raw()
	require.NoError(t, err)
	assert.Equal(t, []byte("test-wallet-123"), raw)
}

func TestGenerateKeyMessage_Sig(t *testing.T) {
	signature := []byte("test-signature-bytes")
	msg := &GenerateKeyMessage{
		WalletID:  "test-wallet",
		Signature: signature,
	}

	assert.Equal(t, signature, msg.Sig())
}

func TestGenerateKeyMessage_InitiatorID(t *testing.T) {
	walletID := "test-wallet-456"
	msg := &GenerateKeyMessage{
		WalletID:  walletID,
		Signature: []byte("signature"),
	}

	assert.Equal(t, walletID, msg.InitiatorID())
}

func TestSignTxMessage_Raw(t *testing.T) {
	msg := &SignTxMessage{
		KeyType:             KeyTypeSecp256k1,
		WalletID:            "wallet-123",
		NetworkInternalCode: "BTC",
		TxID:                "tx-456",
		Tx:                  []byte("transaction-data"),
		Signature:           []byte("signature-data"),
	}

	raw, err := msg.Raw()
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	// Verify the raw data is valid JSON and doesn't contain signature
	assert.NotContains(t, string(raw), "signature-data")
	assert.Contains(t, string(raw), "wallet-123")
	assert.Contains(t, string(raw), "secp256k1")
	assert.Contains(t, string(raw), "BTC")
	assert.Contains(t, string(raw), "tx-456")
}

func TestSignTxMessage_Sig(t *testing.T) {
	signature := []byte("transaction-signature")
	msg := &SignTxMessage{
		KeyType:             KeyTypeEd25519,
		WalletID:            "wallet",
		NetworkInternalCode: "ETH",
		TxID:                "tx",
		Tx:                  []byte("tx-data"),
		Signature:           signature,
	}

	assert.Equal(t, signature, msg.Sig())
}

func TestSignTxMessage_InitiatorID(t *testing.T) {
	txID := "transaction-789"
	msg := &SignTxMessage{
		KeyType:             KeyTypeSecp256k1,
		WalletID:            "wallet",
		NetworkInternalCode: "BTC",
		TxID:                txID,
		Tx:                  []byte("data"),
		Signature:           []byte("sig"),
	}

	assert.Equal(t, txID, msg.InitiatorID())
}

func TestResharingMessage_Raw(t *testing.T) {
	msg := &ResharingMessage{
		NodeIDs:      []string{"node1", "node2", "node3"},
		NewThreshold: 2,
		KeyType:      KeyTypeEd25519,
		WalletID:     "reshare-wallet",
		Signature:    []byte("reshare-signature"),
	}

	raw, err := msg.Raw()
	require.NoError(t, err)

	type data struct {
		SessionID    string   `json:"session_id"`
		NodeIDs      []string `json:"node_ids"` // new peer IDs
		NewThreshold int      `json:"new_threshold"`
		KeyType      KeyType  `json:"key_type"`
		WalletID     string   `json:"wallet_id"`
	}

	d := data{
		SessionID:    msg.SessionID,
		NodeIDs:      msg.NodeIDs,
		NewThreshold: msg.NewThreshold,
		KeyType:      msg.KeyType,
		WalletID:     msg.WalletID,
	}

	expectedBytes, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Equal(t, expectedBytes, raw)
}

func TestResharingMessage_Sig(t *testing.T) {
	signature := []byte("resharing-signature")
	msg := &ResharingMessage{
		NodeIDs:      []string{"node1", "node2"},
		NewThreshold: 1,
		KeyType:      KeyTypeSecp256k1,
		WalletID:     "wallet",
		Signature:    signature,
	}

	assert.Equal(t, signature, msg.Sig())
}

func TestResharingMessage_InitiatorID(t *testing.T) {
	walletID := "reshare-wallet-123"
	msg := &ResharingMessage{
		NodeIDs:      []string{"node1"},
		NewThreshold: 0,
		KeyType:      KeyTypeEd25519,
		WalletID:     walletID,
		Signature:    []byte("sig"),
	}

	assert.Equal(t, walletID, msg.InitiatorID())
}

func TestSignTxMessage_RawConsistency(t *testing.T) {
	msg := &SignTxMessage{
		KeyType:             KeyTypeSecp256k1,
		WalletID:            "consistent-wallet",
		NetworkInternalCode: "BTC",
		TxID:                "consistent-tx",
		Tx:                  []byte("consistent-data"),
		Signature:           []byte("signature1"),
	}

	raw1, err1 := msg.Raw()
	require.NoError(t, err1)

	// Change signature and verify raw data remains the same
	msg.Signature = []byte("different-signature")
	raw2, err2 := msg.Raw()
	require.NoError(t, err2)

	assert.Equal(t, raw1, raw2, "Raw data should be consistent regardless of signature")
}

func TestAllMessageTypesImplementInitiatorMessage(t *testing.T) {
	var _ InitiatorMessage = &GenerateKeyMessage{}
	var _ InitiatorMessage = &SignTxMessage{}
	var _ InitiatorMessage = &ResharingMessage{}
}

func TestSignTxMessage_EmptyValues(t *testing.T) {
	msg := &SignTxMessage{
		KeyType:             "",
		WalletID:            "",
		NetworkInternalCode: "",
		TxID:                "",
		Tx:                  nil,
		Signature:           nil,
	}

	raw, err := msg.Raw()
	require.NoError(t, err)
	assert.NotEmpty(t, raw) // Should still produce valid JSON

	assert.Empty(t, msg.Sig())
	assert.Empty(t, msg.InitiatorID())
}

func TestGenerateKeyMessage_EmptyWallet(t *testing.T) {
	msg := &GenerateKeyMessage{
		WalletID:  "",
		Signature: []byte("sig"),
	}

	raw, err := msg.Raw()
	require.NoError(t, err)
	assert.Equal(t, []byte(""), raw)
	assert.Equal(t, "", msg.InitiatorID())
}
