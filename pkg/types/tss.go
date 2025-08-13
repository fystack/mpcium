package types

import (
	"encoding/json"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

type TssMessage struct {
	WalletID    string         `json:"sessionID"`
	MsgBytes    []byte         `json:"msgBytes"`
	IsBroadcast bool           `json:"isBroadcast"`
	From        *tss.PartyID   `json:"from"`
	To          []*tss.PartyID `json:"to"`

	IsToOldCommittee        bool `json:"isToOldCommittee"`
	IsToOldAndNewCommittees bool `json:"isToOldAndNewCommittees"`

	Signature []byte `json:"signature"`
}

func NewTssMessage(
	walletID string,
	msgBytes []byte,
	isBroadcast bool,
	from *tss.PartyID,
	to []*tss.PartyID,
) TssMessage {
	tssMsg := TssMessage{
		WalletID:    walletID,
		IsBroadcast: isBroadcast,
		MsgBytes:    msgBytes,
		From:        from,
		To:          to,
	}

	return tssMsg
}

func MarshalTssMessage(tssMsg *TssMessage) ([]byte, error) {
	msgBytes, err := json.Marshal(tssMsg)
	if err != nil {
		return []byte{}, err
	}

	return msgBytes, nil
}

func MarshalTssResharingMessage(
	msgBytes []byte,
	isToOldCommittee bool,
	isBroadcast bool,
	isToOldAndNewCommittees bool,
	from *tss.PartyID,
	to []*tss.PartyID,
) ([]byte, error) {
	tssMsg := &TssMessage{
		IsToOldCommittee:        isToOldCommittee,
		IsToOldAndNewCommittees: isToOldAndNewCommittees,
		IsBroadcast:             isBroadcast,
		MsgBytes:                msgBytes,
		From:                    from,
		To:                      to,
	}
	msgBytes, err := json.Marshal(tssMsg)
	if err != nil {
		return []byte{}, err
	}

	return msgBytes, nil
}

func UnmarshalTssMessage(msgBytes []byte) (*TssMessage, error) {
	msg := &TssMessage{}
	err := json.Unmarshal(msgBytes, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

type StartMessage struct {
	Params []byte `json:"params"`
}

func MarshalStartMessage(params []byte) ([]byte, error) {
	startSignMessage := &StartMessage{
		Params: params,
	}

	msgBytes, err := json.Marshal(startSignMessage)
	if err != nil {
		return []byte{}, err
	}

	return msgBytes, nil
}

func UnmarshalStartMessage(msgBytes []byte) (*StartMessage, error) {
	msg := &StartMessage{}
	err := json.Unmarshal(msgBytes, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// MarshalForSigning returns the deterministic JSON bytes for signing
func (msg *TssMessage) MarshalForSigning() ([]byte, error) {
	// Create a map with ordered keys
	signingData := map[string]interface{}{
		"sessionID":               msg.WalletID,
		"msgBytes":                msg.MsgBytes,
		"isBroadcast":             msg.IsBroadcast,
		"from":                    msg.From.Id,
		"to":                      msg.To,
		"isToOldCommittee":        msg.IsToOldCommittee,
		"isToOldAndNewCommittees": msg.IsToOldAndNewCommittees,
	}

	// Use json.Marshal with sorted keys
	return json.Marshal(signingData)
}
