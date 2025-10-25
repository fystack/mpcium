package event

const (
	KeygenBrokerStream   = "mpc-keygen"
	KeygenConsumerStream = "mpc-keygen-consumer"
	KeygenRequestTopic   = "mpc.keygen_request.*"
)

type KeygenResultEvent struct {
	WalletID      string `json:"wallet_id"`
	ECDSAPubKey   []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey   []byte `json:"eddsa_pub_key"`
	CGGMP21PubKey []byte `json:"cggmp21_pub_key"`
	TaprootPubKey []byte `json:"taproot_pub_key"`

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`
}

// CreateKeygenFailureEvent creates a failed keygen event
func CreateKeygenFailureEvent(walletID string, metadata map[string]any) *KeygenResultEvent {
	errorMsg := ""
	if err, ok := metadata["error"].(string); ok {
		errorMsg = err
	}
	return &KeygenResultEvent{
		WalletID:    walletID,
		ResultType:  ResultTypeError,
		ErrorReason: errorMsg,
		ErrorCode:   string(ErrorCodeKeygenFailure),
	}
}
