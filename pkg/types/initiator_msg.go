package types

import "encoding/json"

type KeyType string

const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeEd25519   KeyType = "ed25519"
)

// Protocol selects which MPC backend runs a keygen/signing request.
// Empty (the zero value) means the existing tss-lib backend — every message
// without this field (all pre-existing clients) keeps behaving exactly as
// before.
type Protocol string

const (
	ProtocolDkls23 Protocol = "dkls23"
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
	// Protocol, when set to ProtocolDkls23, additionally runs a DKLs23 keygen
	// alongside the default ECDSA+EdDSA (tss-lib) keys. Omitted/empty is a no-op.
	Protocol Protocol `json:"protocol,omitempty"`
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
	// Protocol, when set to ProtocolDkls23, signs with the wallet's DKLs23 key
	// instead of the tss-lib key selected by KeyType. Omitted/empty is a no-op.
	Protocol Protocol `json:"protocol,omitempty"`
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
		KeyType             KeyType  `json:"key_type"`
		WalletID            string   `json:"wallet_id"`
		NetworkInternalCode string   `json:"network_internal_code"`
		TxID                string   `json:"tx_id"`
		Tx                  []byte   `json:"tx"`
		DerivationPath      []uint32 `json:"derivation_path,omitempty"`
		Protocol            Protocol `json:"protocol,omitempty"`
	}{
		KeyType:             m.KeyType,
		WalletID:            m.WalletID,
		NetworkInternalCode: m.NetworkInternalCode,
		TxID:                m.TxID,
		Tx:                  m.Tx,
		DerivationPath:      m.DerivationPath,
		Protocol:            m.Protocol,
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
