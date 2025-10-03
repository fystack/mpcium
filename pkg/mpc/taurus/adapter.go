package taurus

import (
	"encoding/json"
	"log/slog"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type NetworkInterface interface {
	Next() <-chan *protocol.Message
	Send(msg *protocol.Message)
	Done() <-chan struct{}
}

type TaurusNetworkAdapter struct {
	sid       string
	selfID    party.ID
	transport Transport
	inbox     chan *protocol.Message
	done      chan struct{}
	peers     party.IDSlice
}

func NewTaurusNetworkAdapter(
	sid string,
	selfID party.ID,
	t Transport,
	peers party.IDSlice,
) *TaurusNetworkAdapter {
	a := &TaurusNetworkAdapter{
		sid:       sid,
		selfID:    selfID,
		transport: t,
		inbox:     make(chan *protocol.Message, 100),
		done:      make(chan struct{}),
		peers:     peers,
	}
	go a.route()
	return a
}

func (a *TaurusNetworkAdapter) Next() <-chan *protocol.Message { return a.inbox }
func (a *TaurusNetworkAdapter) Done() <-chan struct{}          { return a.done }

func (a *TaurusNetworkAdapter) Send(msg *protocol.Message) {
	wire, err := json.Marshal(msg)
	if err != nil {
		slog.Error("❌ marshal protocol msg", "err", err)
		return
	}
	m := Msg{SID: a.sid, From: string(msg.From), IsBroadcast: msg.Broadcast, Data: wire}
	for _, pid := range a.peers {
		if pid == a.selfID {
			continue
		}
		if msg.Broadcast || msg.IsFor(pid) {
			_ = a.transport.Send(string(pid), m)
		}
	}
}

func (a *TaurusNetworkAdapter) route() {
	for {
		select {
		case tm, ok := <-a.transport.Inbox():
			if !ok {
				close(a.done)
				return
			}
			var pm protocol.Message
			if err := json.Unmarshal(tm.Data, &pm); err != nil {
				slog.Error("❌ unmarshal protocol msg", "err", err)
				continue
			}
			select {
			case a.inbox <- &pm:
			default:
				slog.Warn("⚠️ inbox full, drop msg", "self", a.selfID)
			}
		case <-a.transport.Done():
			close(a.done)
			return
		}
	}
}
