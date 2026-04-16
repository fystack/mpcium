package coordinator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type NATSRuntime struct {
	nc       *nats.Conn
	coord    *Coordinator
	presence PresenceView
	subs     []*nats.Subscription
}

func NewNATSRuntime(nc *nats.Conn, coord *Coordinator, presence PresenceView) *NATSRuntime {
	return &NATSRuntime{nc: nc, coord: coord, presence: presence}
}

func (r *NATSRuntime) Start(ctx context.Context) error {
	for _, op := range []Operation{OperationKeygen, OperationSign, OperationReshare} {
		op := op
		sub, err := r.nc.Subscribe(RequestSubject(op), func(msg *nats.Msg) {
			reply, err := r.coord.HandleRequest(ctx, op, msg.Data)
			if err != nil {
				reply = reject(ErrorCodeInternal, err.Error())
			}
			if msg.Reply != "" {
				_ = msg.Respond(reply)
			}
		})
		if err != nil {
			return fmt.Errorf("subscribe request subject %s: %w", RequestSubject(op), err)
		}
		r.subs = append(r.subs, sub)
	}

	eventSub, err := r.nc.Subscribe(AllSessionEventsSubject(), func(msg *nats.Msg) {
		_ = r.coord.HandleSessionEvent(ctx, msg.Data)
	})
	if err != nil {
		return fmt.Errorf("subscribe session events: %w", err)
	}
	r.subs = append(r.subs, eventSub)

	presenceSub, err := r.nc.Subscribe(AllPresenceSubject(), func(msg *nats.Msg) {
		var event sdkprotocol.PresenceEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			return
		}
		_ = r.presence.ApplyPresence(event)
	})
	if err != nil {
		return fmt.Errorf("subscribe presence events: %w", err)
	}
	r.subs = append(r.subs, presenceSub)

	return r.nc.Flush()
}

func (r *NATSRuntime) Stop() error {
	for _, sub := range r.subs {
		if err := sub.Unsubscribe(); err != nil {
			return err
		}
	}
	r.subs = nil
	return nil
}
