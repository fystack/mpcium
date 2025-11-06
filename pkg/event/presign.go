package event

const (
	PresignBrokerStream   = "mpc-presign"
	PresignConsumerStream = "mpc-presign-consumer"
	PresignRequestTopic   = "mpc.presign_request.*"
	PresignResultTopic    = "mpc.mpc_presign_result.*"
)

type PresignResultEvent struct {
	ResultType  ResultType `json:"result_type"`
	ErrorCode   ErrorCode  `json:"error_code"`
	ErrorReason string     `json:"error_reason"`
	IsTimeout   bool       `json:"is_timeout"`
	WalletID    string     `json:"wallet_id"`
	TxID        string     `json:"tx_id"`
	Status      string     `json:"status"`
}
