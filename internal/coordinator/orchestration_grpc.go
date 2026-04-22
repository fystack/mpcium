package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	coordinatorv1 "github.com/fystack/mpcium-sdk/integrations/coordinator-grpc/proto/coordinator/v1"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OrchestrationGRPCServer struct {
	coordinatorv1.UnimplementedCoordinatorOrchestrationServer
	coord        *Coordinator
	pollInterval time.Duration
}

func NewOrchestrationGRPCServer(coord *Coordinator, pollInterval time.Duration) *OrchestrationGRPCServer {
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}
	return &OrchestrationGRPCServer{coord: coord, pollInterval: pollInterval}
}

func (s *OrchestrationGRPCServer) Keygen(ctx context.Context, req *coordinatorv1.KeygenRequest) (*coordinatorv1.RequestAccepted, error) {
	control := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID: "tmp",
			Protocol:  sdkprotocol.ProtocolType(strings.TrimSpace(req.GetProtocol())),
			Operation: sdkprotocol.OperationTypeKeygen,
			Threshold: req.GetThreshold(),
			Keygen: &sdkprotocol.KeygenPayload{
				KeyID: req.GetWalletId(),
			},
		},
	}
	participants, err := mapParticipantsToSDK(req.GetParticipants())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid participants: %v", err)
	}
	control.SessionStart.Participants = participants
	return s.handleOperation(ctx, OperationKeygen, control)
}

func (s *OrchestrationGRPCServer) Sign(ctx context.Context, req *coordinatorv1.SignRequest) (*coordinatorv1.RequestAccepted, error) {
	signingInput, err := decodeOptionalHex(req.GetSigningInputHex())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid signing_input_hex: %v", err)
	}
	derivationDelta, err := decodeOptionalHex(req.GetDerivationDeltaHex())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid derivation_delta_hex: %v", err)
	}

	control := &sdkprotocol.ControlMessage{
		SessionStart: &sdkprotocol.SessionStart{
			SessionID: "tmp",
			Protocol:  sdkprotocol.ProtocolType(strings.TrimSpace(req.GetProtocol())),
			Operation: sdkprotocol.OperationTypeSign,
			Threshold: req.GetThreshold(),
			Sign: &sdkprotocol.SignPayload{
				KeyID:        req.GetWalletId(),
				SigningInput: signingInput,
				Derivation: &sdkprotocol.NonHardenedDerivation{
					Path:  append([]uint32(nil), req.GetDerivationPath()...),
					Delta: derivationDelta,
				},
			},
		},
	}
	participants, err := mapParticipantsToSDK(req.GetParticipants())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid participants: %v", err)
	}
	control.SessionStart.Participants = participants
	if len(req.GetDerivationPath()) == 0 && len(derivationDelta) == 0 {
		control.SessionStart.Sign.Derivation = nil
	}

	return s.handleOperation(ctx, OperationSign, control)
}

func (s *OrchestrationGRPCServer) WaitSessionResult(ctx context.Context, req *coordinatorv1.SessionLookup) (*coordinatorv1.SessionResult, error) {
	sessionID := strings.TrimSpace(req.GetSessionId())
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	if _, ok := s.coord.GetSession(ctx, sessionID); !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		session, ok := s.coord.GetSession(ctx, sessionID)
		if !ok {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		if session.State.Terminal() {
			return sessionToProtoResult(session), nil
		}

		select {
		case <-ctx.Done():
			return nil, status.Error(codes.DeadlineExceeded, "wait session result timeout")
		case <-ticker.C:
		}
	}
}

func (s *OrchestrationGRPCServer) handleOperation(ctx context.Context, op Operation, msg *sdkprotocol.ControlMessage) (*coordinatorv1.RequestAccepted, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal request: %v", err)
	}

	replyRaw, err := s.coord.HandleRequest(ctx, op, raw)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "handle request: %v", err)
	}

	var accepted sdkprotocol.RequestAccepted
	if err := json.Unmarshal(replyRaw, &accepted); err == nil && accepted.Accepted {
		return &coordinatorv1.RequestAccepted{
			Accepted:  true,
			SessionId: accepted.SessionID,
			ExpiresAt: accepted.ExpiresAt,
		}, nil
	}

	var rejected sdkprotocol.RequestRejected
	if err := json.Unmarshal(replyRaw, &rejected); err == nil && !rejected.Accepted {
		return &coordinatorv1.RequestAccepted{
			Accepted:     false,
			ErrorCode:    rejected.ErrorCode,
			ErrorMessage: rejected.ErrorMessage,
		}, nil
	}

	return nil, status.Error(codes.Internal, "unexpected coordinator response")
}

func mapParticipantsToSDK(participants []*coordinatorv1.Participant) ([]*sdkprotocol.SessionParticipant, error) {
	mapped := make([]*sdkprotocol.SessionParticipant, 0, len(participants))
	for _, participant := range participants {
		if participant == nil {
			continue
		}
		pubKey, err := decodeOptionalHex(participant.GetIdentityPublicKeyHex())
		if err != nil {
			return nil, fmt.Errorf("participant %q identity_public_key_hex: %w", participant.GetId(), err)
		}
		id := strings.TrimSpace(participant.GetId())
		mapped = append(mapped, &sdkprotocol.SessionParticipant{
			ParticipantID:     id,
			PartyKey:          []byte(id),
			IdentityPublicKey: pubKey,
		})
	}
	return mapped, nil
}

func sessionToProtoResult(session *Session) *coordinatorv1.SessionResult {
	result := &coordinatorv1.SessionResult{
		Completed:    session.State == SessionCompleted,
		SessionId:    session.ID,
		ErrorCode:    session.ErrorCode,
		ErrorMessage: session.ErrorMessage,
	}
	if session.Result == nil {
		return result
	}
	if session.Result.Keygen != nil {
		result.KeyId = session.Result.Keygen.KeyID
	}
	if session.Result.Signature != nil {
		sig := session.Result.Signature
		result.KeyId = sig.KeyID
		result.SignatureHex = hex.EncodeToString(sig.Signature)
		result.SignatureRecoveryHex = hex.EncodeToString(sig.SignatureRecovery)
		result.RHex = hex.EncodeToString(sig.R)
		result.SHex = hex.EncodeToString(sig.S)
		result.SignedInputHex = hex.EncodeToString(sig.SignedInput)
	}
	return result
}

func decodeOptionalHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	return hex.DecodeString(value)
}
