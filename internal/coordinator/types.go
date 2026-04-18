package coordinator

import (
	"time"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type Operation string

const (
	OperationKeygen  Operation = "keygen"
	OperationSign    Operation = "sign"
	OperationReshare Operation = "reshare"
)

func (o Operation) Valid() bool {
	return o == OperationKeygen || o == OperationSign || o == OperationReshare
}

func (o Operation) ToSDK() sdkprotocol.OperationType {
	switch o {
	case OperationKeygen:
		return sdkprotocol.OperationTypeKeygen
	case OperationSign:
		return sdkprotocol.OperationTypeSign
	case OperationReshare:
		return sdkprotocol.OperationTypeReshare
	default:
		return sdkprotocol.OperationTypeUnspecified
	}
}

type SessionState string

const (
	SessionCreated             SessionState = "created"
	SessionWaitingParticipants SessionState = "waiting_participants"
	SessionKeyExchange         SessionState = "key_exchange"
	SessionActiveMPC           SessionState = "active_mpc"
	SessionCompleted           SessionState = "completed"
	SessionFailed              SessionState = "failed"
	SessionExpired             SessionState = "expired"
)

func (s SessionState) Terminal() bool {
	return s == SessionCompleted || s == SessionFailed || s == SessionExpired
}

type ParticipantState struct {
	Joined          bool   `json:"joined"`
	Ready           bool   `json:"ready"`
	KeyExchangeDone bool   `json:"key_exchange_done"`
	Completed       bool   `json:"completed"`
	Failed          bool   `json:"failed"`
	LastSequence    uint64 `json:"last_sequence"`
	ResultHash      string `json:"result_hash,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

type Session struct {
	ID               string                            `json:"id"`
	RequestID        string                            `json:"request_id"`
	Op               Operation                         `json:"op"`
	State            SessionState                      `json:"state"`
	Start            *sdkprotocol.SessionStart         `json:"start"`
	Participants     []*sdkprotocol.SessionParticipant `json:"participants"`
	ParticipantState map[string]*ParticipantState      `json:"participant_state"`
	ExchangeID       string                            `json:"exchange_id,omitempty"`
	ResultHash       string                            `json:"result_hash,omitempty"`
	Result           *sdkprotocol.Result               `json:"result,omitempty"`
	ErrorCode        string                            `json:"error_code,omitempty"`
	ErrorMessage     string                            `json:"error_message,omitempty"`
	CreatedAt        time.Time                         `json:"created_at"`
	UpdatedAt        time.Time                         `json:"updated_at"`
	ExpiresAt        time.Time                         `json:"expires_at"`
	CompletedAt      *time.Time                        `json:"completed_at,omitempty"`
	ControlSeq       uint64                            `json:"control_seq"`
	ParticipantKeys  map[string][]byte                 `json:"participant_keys"`
}
