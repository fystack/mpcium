package event

const (
	SigningPublisherStream     = "mpc-signing"
	SigningConsumerStream      = "mpc-signing-consumer"
	SigningRequestTopic        = "mpc.signing_request.*"
	SigningResultTopic         = "mpc.mpc_signing_result.*"
	SigningResultCompleteTopic = "mpc.mpc_signing_result.complete"
)

type SigningResultEvent struct {
	ResultType          ResultType `json:"result_type"`
	ErrorCode           ErrorCode  `json:"error_code"`
	ErrorReason         string     `json:"error_reason"`
	IsTimeout           bool       `json:"is_timeout"`
	NetworkInternalCode string     `json:"network_internal_code"`
	WalletID            string     `json:"wallet_id"`
	TxID                string     `json:"tx_id"`
	R                   []byte     `json:"r"`
	S                   []byte     `json:"s"`
	SignatureRecovery   []byte     `json:"signature_recovery"`

	// TODO: define two separate events for eddsa and ecdsa
	Signature []byte `json:"signature"`

	// NodeID and ResultSignature identify and authenticate the node that
	// emitted this result, so consumers can reject events injected or
	// tampered with by a compromised message broker.
	NodeID          string `json:"node_id,omitempty"`
	ResultSignature []byte `json:"result_signature,omitempty"`
}

type SigningResultSuccessEvent struct {
	NetworkInternalCode string `json:"network_internal_code"`
	WalletID            string `json:"wallet_id"`
	TxID                string `json:"tx_id"`
	R                   []byte `json:"r"`
	S                   []byte `json:"s"`
	SignatureRecovery   []byte `json:"signature_recovery"`

	// TODO: define two separate events for eddsa and ecdsa
	Signature []byte `json:"signature"`
}

type SigningResultErrorEvent struct {
	NetworkInternalCode string    `json:"network_internal_code"`
	WalletID            string    `json:"wallet_id"`
	TxID                string    `json:"tx_id"`
	ErrorCode           ErrorCode `json:"error_code"`
	ErrorReason         string    `json:"error_reason"`
	IsTimeout           bool      `json:"is_timeout"`
}
