package event

const (
	KeygenBrokerStream   = "mpc-keygen"
	KeygenConsumerStream = "mpc-keygen-consumer"
	KeygenRequestTopic   = "mpc.keygen_request.*"
)

type KeygenResultEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
	// DKLSPubKey is set only when the request opted in via Protocol=dkls23.
	DKLSPubKey []byte `json:"dkls_pub_key,omitempty"`
	// DKLSChainCode lets clients derive non-hardened child public keys offline.
	DKLSChainCode []byte `json:"dkls_chain_code,omitempty"`

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`
}
