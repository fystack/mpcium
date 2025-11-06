package types

import (
	"encoding/json"
	"errors"
	"fmt"
)

type EventInitiatorKeyType string

const (
	EventInitiatorKeyTypeEd25519 EventInitiatorKeyType = "ed25519"
	EventInitiatorKeyTypeP256    EventInitiatorKeyType = "p256"
)

type KeyType string

const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeEd25519   KeyType = "ed25519"
)

type Protocol string

const (
	ProtocolGG18    Protocol = "gg18"
	ProtocolCGGMP21 Protocol = "cggmp21"
	ProtocolFROST   Protocol = "frost"
	ProtocolTaproot Protocol = "taproot"
)

func (p Protocol) String() string {
	return string(p)
}

// mapping of key types → supported protocols
var supportedProtocols = map[KeyType][]Protocol{
	KeyTypeSecp256k1: {
		ProtocolGG18,
		ProtocolCGGMP21,
		ProtocolFROST,
		ProtocolTaproot,
	},
	KeyTypeEd25519: {
		ProtocolGG18,
	},
}

// ValidateKeyProtocol checks if a key type supports a given protocol.
func ValidateKeyProtocol(keyType KeyType, protocol Protocol) error {
	if keyType == "" || protocol == "" {
		return errors.New("key_type and protocol are required")
	}

	supported, ok := supportedProtocols[keyType]
	if !ok {
		return fmt.Errorf("unsupported key_type %q", keyType)
	}

	for _, p := range supported {
		if p == protocol {
			return nil // valid combo
		}
	}

	return fmt.Errorf(
		"protocol %q not supported for key_type %q; expected one of %v",
		protocol, keyType, supported,
	)
}

// InitiatorMessage is anything that carries a payload to verify and its signature.
type InitiatorMessage interface {
	Raw() ([]byte, error)
	Sig() []byte
	InitiatorID() string
}

type GenerateKeyMessage struct {
	WalletID      string   `json:"wallet_id"`
	ECDSAProtocol Protocol `json:"ecdsa_protocol,omitempty"`
	EdDSAProtocol Protocol `json:"eddsa_protocol,omitempty"`
	Signature     []byte   `json:"signature"`
}

type SignTxMessage struct {
	KeyType             KeyType  `json:"key_type"`
	Protocol            Protocol `json:"protocol,omitempty"`
	WalletID            string   `json:"wallet_id"`
	NetworkInternalCode string   `json:"network_internal_code"`
	TxID                string   `json:"tx_id"`
	Tx                  []byte   `json:"tx"`
	Signature           []byte   `json:"signature"`
}

type ResharingMessage struct {
	SessionID    string   `json:"session_id"`
	NodeIDs      []string `json:"node_ids"` // new peer IDs
	NewThreshold int      `json:"new_threshold"`
	KeyType      KeyType  `json:"key_type"`
	Protocol     Protocol `json:"protocol,omitempty"`
	WalletID     string   `json:"wallet_id"`
	Signature    []byte   `json:"signature,omitempty"`
}

type PresignTxMessage struct {
	KeyType   KeyType  `json:"key_type"`
	Protocol  Protocol `json:"protocol"`
	WalletID  string   `json:"wallet_id"`
	TxID      string   `json:"tx_id"`
	Signature []byte   `json:"signature"`
}

func (m *GenerateKeyMessage) Raw() ([]byte, error) {
	payload := struct {
		WalletID      string   `json:"wallet_id"`
		ECDSAProtocol Protocol `json:"ecdsa_protocol,omitempty"`
		EdDSAProtocol Protocol `json:"eddsa_protocol,omitempty"`
	}{
		WalletID:      m.WalletID,
		ECDSAProtocol: m.ECDSAProtocol,
		EdDSAProtocol: m.EdDSAProtocol,
	}
	return json.Marshal(payload)
}

func (m *GenerateKeyMessage) Sig() []byte {
	return m.Signature
}

func (m *GenerateKeyMessage) InitiatorID() string {
	return m.WalletID
}

func (m *SignTxMessage) Raw() ([]byte, error) {
	payload := struct {
		KeyType             KeyType `json:"key_type"`
		WalletID            string  `json:"wallet_id"`
		NetworkInternalCode string  `json:"network_internal_code"`
		TxID                string  `json:"tx_id"`
		Tx                  []byte  `json:"tx"`
	}{
		KeyType:             m.KeyType,
		WalletID:            m.WalletID,
		NetworkInternalCode: m.NetworkInternalCode,
		TxID:                m.TxID,
		Tx:                  m.Tx,
	}
	return json.Marshal(payload)
}

func (m *SignTxMessage) Sig() []byte {
	return m.Signature
}

func (m *SignTxMessage) InitiatorID() string {
	return m.TxID
}

func (m *ResharingMessage) Raw() ([]byte, error) {
	copy := *m
	copy.Signature = nil
	return json.Marshal(&copy)
}

func (m *ResharingMessage) Sig() []byte {
	return m.Signature
}

func (m *ResharingMessage) InitiatorID() string {
	return m.WalletID
}

func (m *PresignTxMessage) Raw() ([]byte, error) {
	payload := struct {
		KeyType  KeyType  `json:"key_type"`
		Protocol Protocol `json:"protocol"`
		WalletID string   `json:"wallet_id"`
		TxID     string   `json:"tx_id"`
	}{
		KeyType:  m.KeyType,
		Protocol: m.Protocol,
		WalletID: m.WalletID,
		TxID:     m.TxID,
	}
	return json.Marshal(payload)
}

func (m *PresignTxMessage) Sig() []byte {
	return m.Signature
}

func (m *PresignTxMessage) InitiatorID() string {
	return m.WalletID
}
