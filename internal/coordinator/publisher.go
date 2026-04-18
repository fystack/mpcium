package coordinator

import (
	"context"
	"encoding/json"
	"fmt"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/nats-io/nats.go"
)

type ControlPublisher interface {
	PublishControl(ctx context.Context, participantID string, control *sdkprotocol.ControlMessage) error
}

type ResultPublisher interface {
	PublishResult(ctx context.Context, sessionID string, result *sdkprotocol.Result) error
}

type NATSControlPublisher struct {
	nc *nats.Conn
}

func NewNATSControlPublisher(nc *nats.Conn) *NATSControlPublisher {
	return &NATSControlPublisher{nc: nc}
}

func (p *NATSControlPublisher) PublishControl(ctx context.Context, participantID string, control *sdkprotocol.ControlMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(control)
	if err != nil {
		return fmt.Errorf("marshal control: %w", err)
	}
	return p.nc.Publish(PeerControlSubject(participantID), raw)
}

type NATSResultPublisher struct {
	nc *nats.Conn
}

func NewNATSResultPublisher(nc *nats.Conn) *NATSResultPublisher {
	return &NATSResultPublisher{nc: nc}
}

func (p *NATSResultPublisher) PublishResult(ctx context.Context, sessionID string, result *sdkprotocol.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	return p.nc.Publish(SessionResultSubject(sessionID), raw)
}
