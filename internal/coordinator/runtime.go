package coordinator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fystack/mpcium/pkg/logger"
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
	logger.Info("starting coordinator runtime subscriptions")

	for _, op := range []Operation{OperationKeygen, OperationSign, OperationReshare} {
		op := op
		sub, err := r.nc.Subscribe(RequestSubject(op), func(msg *nats.Msg) {
			reply, err := r.coord.HandleRequest(ctx, op, msg.Data)
			if err != nil {
				logger.Error("handle coordinator request failed", err, "operation", string(op))
				reply = reject(ErrorCodeInternal, err.Error())
			}
			if msg.Reply != "" {
				_ = msg.Respond(reply)
			}
		})
		if err != nil {
			return fmt.Errorf("subscribe request subject %s: %w", RequestSubject(op), err)
		}
		logger.Info("subscribed coordinator request subject", "subject", RequestSubject(op))
		r.subs = append(r.subs, sub)
	}

	eventSub, err := r.nc.Subscribe(AllSessionEventsSubject(), func(msg *nats.Msg) {
		if err := r.coord.HandleSessionEvent(ctx, msg.Data); err != nil {
			logger.Error("handle session event failed", err)
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe session events: %w", err)
	}
	logger.Info("subscribed coordinator session events", "subject", AllSessionEventsSubject())
	r.subs = append(r.subs, eventSub)

	presenceSub, err := r.nc.Subscribe(AllPresenceSubject(), func(msg *nats.Msg) {
		var event sdkprotocol.PresenceEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			logger.Error("decode presence event failed", err)
			return
		}
		_ = r.presence.ApplyPresence(event)
	})
	if err != nil {
		return fmt.Errorf("subscribe presence events: %w", err)
	}
	logger.Info("subscribed coordinator presence events", "subject", AllPresenceSubject())
	r.subs = append(r.subs, presenceSub)

	return r.nc.Flush()
}

func (r *NATSRuntime) Stop() error {
	logger.Info("stopping coordinator runtime subscriptions")
	for _, sub := range r.subs {
		if err := sub.Unsubscribe(); err != nil {
			return err
		}
	}
	r.subs = nil
	return nil
}
