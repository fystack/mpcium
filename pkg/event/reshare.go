package event

import "github.com/fystack/mpcium/pkg/types"

type ResharingResultEvent struct {
	SessionID    string        `json:"session_id"`
	WalletID     string        `json:"wallet_id"`
	NewThreshold int           `json:"new_threshold"`
	KeyType      types.KeyType `json:"key_type"`
	PubKey       []byte        `json:"pub_key"`

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`

	// NodeID and ResultSignature authenticate the node that emitted this
	// result; see SigningResultEvent.
	NodeID          string `json:"node_id,omitempty"`
	ResultSignature []byte `json:"result_signature,omitempty"`
}
