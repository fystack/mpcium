package mpc

import "github.com/fystack/mpcium/pkg/messaging"

const (
	TypeResharingSuccess = "mpc.mpc_resharing_success.%s"
)

type ResharingSession struct {
	Session
	walletID     string
	newThreshold int
}

type ResharingSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

func NewResharingSession(
	walletID string,
	newThreshold int,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,

) *ResharingSession {
	return &ResharingSession{
		walletID:     walletID,
		newThreshold: newThreshold,
	}
}

func (s *ResharingSession) Init() {

}

func (s *ResharingSession) Resharing(done func()) {

}
