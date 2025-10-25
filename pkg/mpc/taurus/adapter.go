package taurus

import (
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type NetworkAdapter struct {
	sid       string
	selfID    party.ID
	peers     party.IDSlice
	transport Transport
	inbox     chan *protocol.Message
}

func NewNetworkAdapter(
	sid string,
	selfID party.ID,
	t Transport,
	peers party.IDSlice,
) *NetworkAdapter {
	a := &NetworkAdapter{
		sid:       sid,
		selfID:    selfID,
		peers:     peers,
		transport: t,
		inbox:     make(chan *protocol.Message, 100),
	}
	go a.route()
	return a
}

func (a *NetworkAdapter) Next() <-chan *protocol.Message { return a.inbox }

func (a *NetworkAdapter) Send(msg *protocol.Message) {
	wire, err := msg.MarshalBinary()
	if err != nil {
		logger.Error("marshal protocol msg", err)
		return
	}
	m := types.TaurusMessage{
		SID:         a.sid,
		From:        string(msg.From),
		To:          []string{string(msg.To)},
		IsBroadcast: msg.Broadcast,
		Data:        wire,
	}
	for _, pid := range a.peers {
		if pid != a.selfID && (msg.Broadcast || msg.IsFor(pid)) {
			_ = a.transport.Send(string(pid), m)
		}
	}
}

func (a *NetworkAdapter) route() {
	for tm := range a.transport.Inbox() {
		var pm protocol.Message
		if err := pm.UnmarshalBinary(tm.Data); err != nil {
			logger.Error("unmarshal protocol msg", err)
			continue
		}

		select {
		case a.inbox <- &pm:
		default:
			logger.Warn("inbox full, drop msg", "self", a.selfID)
		}
	}
}
