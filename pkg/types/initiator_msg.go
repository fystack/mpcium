package types

import "encoding/json"

type KeyType string

const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeEd25519   KeyType = "ed25519"
)

type EventInitiatorKeyType string

const (
	EventInitiatorKeyTypeEd25519 EventInitiatorKeyType = "ed25519"
	EventInitiatorKeyTypeP256    EventInitiatorKeyType = "p256"
)

// AuthorizerSignature represents a single authorizer signature attached to an initiator message.
type AuthorizerSignature struct {
	AuthorizerID string `json:"authorizer_id"`
	Signature    []byte `json:"signature"`
}

// InitiatorMessage is anything that carries a payload to verify and its signature.
type InitiatorMessage interface {
	// Raw returns the canonical byte‐slice that was signed.
	Raw() ([]byte, error)
	// Sig returns the signature over Raw().
	Sig() []byte
	// InitiatorID returns the ID whose public key we have to look up.
	InitiatorID() string

	GetAuthorizerSignatures() []AuthorizerSignature
}

type GenerateKeyMessage struct {
	WalletID             string                `json:"wallet_id"`
	Signature            []byte                `json:"signature"`
	AuthorizerSignatures []AuthorizerSignature `json:"authorizer_signatures,omitempty"`
}

type SignTxMessage struct {
	KeyType              KeyType               `json:"key_type"`
	WalletID             string                `json:"wallet_id"`
	NetworkInternalCode  string                `json:"network_internal_code"`
	TxID                 string                `json:"tx_id"`
	Tx                   []byte                `json:"tx"`
	Signature            []byte                `json:"signature"`
	DerivationPath       []uint32              `json:"derivation_path"`
	AuthorizerSignatures []AuthorizerSignature `json:"authorizer_signatures,omitempty"`
}

type ResharingMessage struct {
	SessionID            string                `json:"session_id"`
	NodeIDs              []string              `json:"node_ids"` // new peer IDs
	NewThreshold         int                   `json:"new_threshold"`
	KeyType              KeyType               `json:"key_type"`
	WalletID             string                `json:"wallet_id"`
	Signature            []byte                `json:"signature,omitempty"`
	AuthorizerSignatures []AuthorizerSignature `json:"authorizer_signatures,omitempty"`
}

func (m *SignTxMessage) Raw() ([]byte, error) {
	// omit the Signature field itself when computing the signed‐over data
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

func (m *GenerateKeyMessage) Raw() ([]byte, error) {
	return []byte(m.WalletID), nil
}

func (m *GenerateKeyMessage) Sig() []byte {
	return m.Signature
}

func (m *GenerateKeyMessage) InitiatorID() string {
	return m.WalletID
}

func (m *GenerateKeyMessage) GetAuthorizerSignatures() []AuthorizerSignature {
	return m.AuthorizerSignatures
}

func (m *ResharingMessage) Raw() ([]byte, error) {
	copy := *m           // create a shallow copy
	copy.Signature = nil // modify only the copy
	copy.AuthorizerSignatures = nil
	return json.Marshal(&copy)
}

func (m *ResharingMessage) Sig() []byte {
	return m.Signature
}

func (m *ResharingMessage) InitiatorID() string {
	return m.WalletID
}

func (m *ResharingMessage) GetAuthorizerSignatures() []AuthorizerSignature {
	return m.AuthorizerSignatures
}

func (m *SignTxMessage) GetAuthorizerSignatures() []AuthorizerSignature {
	return m.AuthorizerSignatures
}

// ComposeAuthorizerRaw composes the raw data to be signed by an authorizer
func ComposeAuthorizerRaw(msg InitiatorMessage) ([]byte, error) {
	raw, err := msg.Raw()
	if err != nil {
		return nil, err
	}

	payload := struct {
		InitiatorID  string `json:"initiator_id"`
		InitiatorRaw []byte `json:"initiator_raw"`
		InitiatorSig []byte `json:"initiator_sig"`
	}{
		InitiatorID:  msg.InitiatorID(),
		InitiatorRaw: raw,
		InitiatorSig: msg.Sig(),
	}

	return json.Marshal(payload)
}
