package coordinatorclient

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

const (
	topicPrefix          = "mpc.v1"
	requestKeygenSubject = topicPrefix + ".request.keygen"
	requestSignSubject   = topicPrefix + ".request.sign"
)

type Client struct {
	nc      *nats.Conn
	timeout time.Duration
}

type Config struct {
	NATSURL string
	Timeout time.Duration
}

type KeygenParticipant struct {
	ID                string
	IdentityPublicKey []byte
}

type SignParticipant = KeygenParticipant

type KeygenRequest struct {
	Protocol     sdkprotocol.ProtocolType
	Threshold    uint32
	WalletID     string
	Participants []KeygenParticipant
}

type SignRequest struct {
	Protocol     sdkprotocol.ProtocolType
	Threshold    uint32
	WalletID     string
	SigningInput []byte
	Derivation   *sdkprotocol.NonHardenedDerivation
	Participants []SignParticipant
}

func New(cfg Config) (*Client, error) {
	if cfg.NATSURL == "" {
		cfg.NATSURL = nats.DefaultURL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}

	return &Client{
		nc:      nc,
		timeout: cfg.Timeout,
	}, nil
}

func (c *Client) Close() {
	if c == nil || c.nc == nil {
		return
	}
	c.nc.Close()
}

func (c *Client) PublishPresence(ctx context.Context, peerID string) error {
	if peerID == "" {
		return fmt.Errorf("peerID is required")
	}

	event := &sdkprotocol.PresenceEvent{
		PeerID:         peerID,
		Status:         sdkprotocol.PresenceStatusOnline,
		Transport:      sdkprotocol.TransportTypeNATS,
		LastSeenUnixMs: time.Now().UTC().UnixMilli(),
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal presence event: %w", err)
	}

	subject := fmt.Sprintf("%s.peer.%s.presence", topicPrefix, peerID)
	if err := c.nc.Publish(subject, payload); err != nil {
		return fmt.Errorf("publish presence: %w", err)
	}

	return c.nc.FlushWithContext(ctx)
}

func (c *Client) RequestKeygen(ctx context.Context, req KeygenRequest) (*sdkprotocol.RequestAccepted, error) {
	if err := validateKeygenRequest(req); err != nil {
		return nil, err
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	msg := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID:    "tmp", // coordinator replaces this value when accepting request
			Protocol:     normalizeProtocol(req.Protocol),
			Operation:    sdkprotocol.OperationTypeKeygen,
			Threshold:    req.Threshold,
			Participants: mapParticipants(req.Participants),
			Keygen: &sdkprotocol.KeygenPayload{
				KeyID: req.WalletID,
			},
		},
	}

	return c.requestSession(ctx, requestKeygenSubject, msg, "keygen")
}

func (c *Client) RequestSign(ctx context.Context, req SignRequest) (*sdkprotocol.RequestAccepted, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	msg := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID:    "tmp", // coordinator replaces this value when accepting request
			Protocol:     normalizeProtocol(req.Protocol),
			Operation:    sdkprotocol.OperationTypeSign,
			Threshold:    req.Threshold,
			Participants: mapParticipants(req.Participants),
			Sign: &sdkprotocol.SignPayload{
				KeyID:        req.WalletID,
				SigningInput: append([]byte(nil), req.SigningInput...),
				Derivation:   req.Derivation,
			},
		},
	}

	return c.requestSession(ctx, requestSignSubject, msg, "sign")
}

func (c *Client) requestSession(ctx context.Context, subject string, msg *sdkprotocol.ControlMessage, action string) (*sdkprotocol.RequestAccepted, error) {
	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s request: %w", action, err)
	}

	respMsg, err := c.nc.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", action, err)
	}

	var accepted sdkprotocol.RequestAccepted
	if err := json.Unmarshal(respMsg.Data, &accepted); err == nil && accepted.Accepted {
		return &accepted, nil
	}

	var rejected sdkprotocol.RequestRejected
	if err := json.Unmarshal(respMsg.Data, &rejected); err == nil && !rejected.Accepted {
		return nil, fmt.Errorf("coordinator rejected request (%s): %s", rejected.ErrorCode, rejected.ErrorMessage)
	}

	return nil, fmt.Errorf("unexpected coordinator response: %s", string(respMsg.Data))
}

func normalizeProtocol(protocol sdkprotocol.ProtocolType) sdkprotocol.ProtocolType {
	if string(protocol) == "" {
		return sdkprotocol.ProtocolTypeUnspecified
	}
	return protocol
}

func (c *Client) WaitSessionResult(ctx context.Context, sessionID string) (*sdkprotocol.Result, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID is required")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	subject := fmt.Sprintf("%s.session.%s.result", topicPrefix, sessionID)
	sub, err := c.nc.SubscribeSync(subject)
	if err != nil {
		return nil, fmt.Errorf("subscribe session result: %w", err)
	}
	defer sub.Unsubscribe()

	if err := c.nc.FlushWithContext(ctx); err != nil {
		return nil, fmt.Errorf("flush subscribe: %w", err)
	}

	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait session result: %w", err)
	}

	var result *sdkprotocol.Result
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("decode session result: %w", err)
	}
	return result, nil
}

func validateKeygenRequest(req KeygenRequest) error {
	if req.WalletID == "" {
		return fmt.Errorf("walletID is required")
	}
	if len(req.Participants) == 0 {
		return fmt.Errorf("participants are required")
	}
	if req.Threshold < 1 || int(req.Threshold) >= len(req.Participants) {
		return fmt.Errorf("invalid threshold %d for %d participants", req.Threshold, len(req.Participants))
	}
	for _, participant := range req.Participants {
		if participant.ID == "" {
			return fmt.Errorf("participant ID is required")
		}
		if len(participant.IdentityPublicKey) == 0 {
			return fmt.Errorf("identity public key is required for participant %q", participant.ID)
		}
	}
	return nil
}

func validateSignRequest(req SignRequest) error {
	if req.Protocol == sdkprotocol.ProtocolTypeUnspecified || string(req.Protocol) == "" {
		return fmt.Errorf("protocol is required")
	}
	if len(req.SigningInput) == 0 {
		return fmt.Errorf("signingInput is required")
	}
	if err := validateKeygenRequest(KeygenRequest{
		Threshold:    req.Threshold,
		WalletID:     req.WalletID,
		Participants: req.Participants,
	}); err != nil {
		return err
	}
	return nil
}

func mapParticipants(participants []KeygenParticipant) []*sdkprotocol.SessionParticipant {
	mapped := make([]*sdkprotocol.SessionParticipant, 0, len(participants))
	for _, participant := range participants {
		mapped = append(mapped, &sdkprotocol.SessionParticipant{
			ParticipantID:     participant.ID,
			PartyKey:          []byte(participant.ID),
			IdentityPublicKey: participant.IdentityPublicKey,
		})
	}
	return mapped
}
