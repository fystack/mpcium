package coordinatorclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	coordinatorv1 "github.com/fystack/mpcium-sdk/integrations/coordinator-grpc/proto/coordinator/v1"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	topicPrefix          = "mpc.v1"
	requestKeygenSubject = topicPrefix + ".request.keygen"
	requestSignSubject   = topicPrefix + ".request.sign"
)

type Client struct {
	nc         *nats.Conn
	grpcConn   *grpc.ClientConn
	grpcClient coordinatorv1.CoordinatorOrchestrationClient
	timeout    time.Duration
	transport  transportType
}

type Config struct {
	NATSURL     string
	GRPCAddress string
	Timeout     time.Duration
}

type transportType string

const (
	transportNATS transportType = "nats"
	transportGRPC transportType = "grpc"
)

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
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.GRPCAddress != "" {
		conn, err := grpc.Dial(
			cfg.GRPCAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return nil, fmt.Errorf("connect to gRPC coordinator: %w", err)
		}
		return &Client{
			grpcConn:   conn,
			grpcClient: coordinatorv1.NewCoordinatorOrchestrationClient(conn),
			timeout:    cfg.Timeout,
			transport:  transportGRPC,
		}, nil
	}
	if cfg.NATSURL == "" {
		cfg.NATSURL = nats.DefaultURL
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}

	return &Client{
		nc:        nc,
		timeout:   cfg.Timeout,
		transport: transportNATS,
	}, nil
}

func (c *Client) Close() {
	if c == nil {
		return
	}
	if c.nc != nil {
		c.nc.Close()
	}
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
	}
}

func (c *Client) PublishPresence(ctx context.Context, peerID string) error {
	if c.transport != transportNATS {
		return fmt.Errorf("presence publishing is supported only in NATS mode")
	}
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

	if c.transport == transportGRPC {
		return c.requestKeygenGRPC(ctx, req)
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

	return c.requestSessionNATS(ctx, requestKeygenSubject, msg, "keygen")
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

	if c.transport == transportGRPC {
		return c.requestSignGRPC(ctx, req)
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

	return c.requestSessionNATS(ctx, requestSignSubject, msg, "sign")
}

func (c *Client) requestSessionNATS(ctx context.Context, subject string, msg *sdkprotocol.ControlMessage, action string) (*sdkprotocol.RequestAccepted, error) {
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
	value := strings.TrimSpace(string(protocol))
	if value == "" {
		return sdkprotocol.ProtocolTypeUnspecified
	}
	return sdkprotocol.ProtocolType(value)
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

	if c.transport == transportGRPC {
		return c.waitSessionResultGRPC(ctx, sessionID)
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

func (c *Client) requestKeygenGRPC(ctx context.Context, req KeygenRequest) (*sdkprotocol.RequestAccepted, error) {
	grpcReq := &coordinatorv1.KeygenRequest{
		Protocol:     string(normalizeProtocol(req.Protocol)),
		Threshold:    req.Threshold,
		WalletId:     req.WalletID,
		Participants: mapParticipantsToProto(req.Participants),
	}
	resp, err := c.grpcClient.Keygen(ctx, grpcReq)
	if err != nil {
		return nil, fmt.Errorf("request keygen: %w", err)
	}
	if !resp.GetAccepted() {
		return nil, fmt.Errorf("coordinator rejected request (%s): %s", resp.GetErrorCode(), resp.GetErrorMessage())
	}
	return &sdkprotocol.RequestAccepted{
		Accepted:  true,
		SessionID: resp.GetSessionId(),
		ExpiresAt: resp.GetExpiresAt(),
	}, nil
}

func (c *Client) requestSignGRPC(ctx context.Context, req SignRequest) (*sdkprotocol.RequestAccepted, error) {
	grpcReq := &coordinatorv1.SignRequest{
		Protocol:        string(req.Protocol),
		Threshold:       req.Threshold,
		WalletId:        req.WalletID,
		SigningInputHex: hex.EncodeToString(req.SigningInput),
		Participants:    mapParticipantsToProto(req.Participants),
	}
	if req.Derivation != nil {
		grpcReq.DerivationPath = append([]uint32(nil), req.Derivation.Path...)
		grpcReq.DerivationDeltaHex = hex.EncodeToString(req.Derivation.Delta)
	}

	resp, err := c.grpcClient.Sign(ctx, grpcReq)
	if err != nil {
		return nil, fmt.Errorf("request sign: %w", err)
	}
	if !resp.GetAccepted() {
		return nil, fmt.Errorf("coordinator rejected request (%s): %s", resp.GetErrorCode(), resp.GetErrorMessage())
	}
	return &sdkprotocol.RequestAccepted{
		Accepted:  true,
		SessionID: resp.GetSessionId(),
		ExpiresAt: resp.GetExpiresAt(),
	}, nil
}

func (c *Client) waitSessionResultGRPC(ctx context.Context, sessionID string) (*sdkprotocol.Result, error) {
	resp, err := c.grpcClient.WaitSessionResult(ctx, &coordinatorv1.SessionLookup{SessionId: sessionID})
	if err != nil {
		return nil, fmt.Errorf("wait session result: %w", err)
	}
	if !resp.GetCompleted() {
		return nil, fmt.Errorf("session failed (%s): %s", resp.GetErrorCode(), resp.GetErrorMessage())
	}

	if resp.GetSignatureHex() != "" || resp.GetSignatureRecoveryHex() != "" || resp.GetRHex() != "" || resp.GetSHex() != "" {
		signature, err := mapProtoSignature(resp)
		if err != nil {
			return nil, err
		}
		return &sdkprotocol.Result{Signature: signature}, nil
	}

	publicKey, err := decodeHexField("public_key_hex", resp.GetPublicKeyHex())
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, err := decodeHexField("ecdsa_pubkey", resp.GetEcdsaPubkey())
	if err != nil {
		return nil, err
	}
	eddsaPubKey, err := decodeHexField("eddsa_pubkey", resp.GetEddsaPubkey())
	if err != nil {
		return nil, err
	}
	return &sdkprotocol.Result{
		KeyShare: &sdkprotocol.KeyShareResult{
			KeyID:       resp.GetKeyId(),
			PublicKey:   publicKey,
			ECDSAPubKey: ecdsaPubKey,
			EDDSAPubKey: eddsaPubKey,
		},
	}, nil
}

func mapParticipantsToProto(participants []KeygenParticipant) []*coordinatorv1.Participant {
	mapped := make([]*coordinatorv1.Participant, 0, len(participants))
	for _, participant := range participants {
		mapped = append(mapped, &coordinatorv1.Participant{
			Id:                   participant.ID,
			IdentityPublicKeyHex: hex.EncodeToString(participant.IdentityPublicKey),
		})
	}
	return mapped
}

func mapProtoSignature(resp *coordinatorv1.SessionResult) (*sdkprotocol.SignatureResult, error) {
	signature, err := decodeHexField("signature_hex", resp.GetSignatureHex())
	if err != nil {
		return nil, err
	}
	recovery, err := decodeHexField("signature_recovery_hex", resp.GetSignatureRecoveryHex())
	if err != nil {
		return nil, err
	}
	r, err := decodeHexField("r_hex", resp.GetRHex())
	if err != nil {
		return nil, err
	}
	s, err := decodeHexField("s_hex", resp.GetSHex())
	if err != nil {
		return nil, err
	}
	signedInput, err := decodeHexField("signed_input_hex", resp.GetSignedInputHex())
	if err != nil {
		return nil, err
	}
	publicKey, err := decodeHexField("public_key_hex", resp.GetPublicKeyHex())
	if err != nil {
		return nil, err
	}
	return &sdkprotocol.SignatureResult{
		KeyID:             resp.GetKeyId(),
		Signature:         signature,
		SignatureRecovery: recovery,
		R:                 r,
		S:                 s,
		SignedInput:       signedInput,
		PublicKey:         publicKey,
	}, nil
}

func decodeHexField(name, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
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
