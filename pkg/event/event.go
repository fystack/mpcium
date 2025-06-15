package event

const (
	KeygenSuccessEventTopic    = "mpc.mpc_keygen_success.*"
	ResharingSuccessEventTopic = "mpc.mpc_resharing_success.*"

	TypeGenerateWalletSuccess = "mpc.mpc_keygen_success.%s"
	TypeSigningResultComplete = "mpc.mpc_signing_result_complete.%s.%s"
	TypeResharingSuccess      = "mpc.mpc_resharing_success.%s"
)

type KeygenSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

type SigningResultEvent struct {
	ResultType          SigningResultType `json:"result_type"`
	ErrorReason         string            `json:"error_reason"`
	IsTimeout           bool              `json:"is_timeout"`
	NetworkInternalCode string            `json:"network_internal_code"`
	WalletID            string            `json:"wallet_id"`
	TxID                string            `json:"tx_id"`
	R                   []byte            `json:"r"`
	S                   []byte            `json:"s"`
	SignatureRecovery   []byte            `json:"signature_recovery"`

	// TODO: define two separate events for eddsa and ecdsa
	Signature []byte `json:"signature"`
}

type ResharingSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}
