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

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`
}
