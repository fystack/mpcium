package coordinatorclient

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	coordinatorv1 "github.com/fystack/mpcium-sdk/integrations/coordinator-grpc/proto/coordinator/v1"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

type fakeCoordinatorServer struct {
	coordinatorv1.UnimplementedCoordinatorOrchestrationServer
	keygenResp *coordinatorv1.RequestAccepted
	signResp   *coordinatorv1.RequestAccepted
	results    map[string]*coordinatorv1.SessionResult
}

func (s *fakeCoordinatorServer) Keygen(context.Context, *coordinatorv1.KeygenRequest) (*coordinatorv1.RequestAccepted, error) {
	if s.keygenResp != nil {
		return s.keygenResp, nil
	}
	return &coordinatorv1.RequestAccepted{
		Accepted:  true,
		SessionId: "sess_keygen",
		ExpiresAt: "2026-04-22T10:00:00Z",
	}, nil
}

func (s *fakeCoordinatorServer) Sign(context.Context, *coordinatorv1.SignRequest) (*coordinatorv1.RequestAccepted, error) {
	if s.signResp != nil {
		return s.signResp, nil
	}
	return &coordinatorv1.RequestAccepted{
		Accepted:  true,
		SessionId: "sess_sign",
		ExpiresAt: "2026-04-22T10:00:00Z",
	}, nil
}

func (s *fakeCoordinatorServer) WaitSessionResult(_ context.Context, req *coordinatorv1.SessionLookup) (*coordinatorv1.SessionResult, error) {
	return s.results[req.GetSessionId()], nil
}

func newTestGRPCClient(t *testing.T, fake *fakeCoordinatorServer) (*Client, func()) {
	t.Helper()
	listener := bufconn.Listen(bufSize)
	server := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorOrchestrationServer(server, fake)
	go func() {
		_ = server.Serve(listener)
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		grpcConn:   conn,
		grpcClient: coordinatorv1.NewCoordinatorOrchestrationClient(conn),
		timeout:    time.Second,
		transport:  transportGRPC,
	}
	cleanup := func() {
		client.Close()
		server.Stop()
		_ = listener.Close()
	}
	return client, cleanup
}

func TestGRPCClientRequestKeygenAndSignResponses(t *testing.T) {
	client, cleanup := newTestGRPCClient(t, &fakeCoordinatorServer{
		signResp: &coordinatorv1.RequestAccepted{
			Accepted:     false,
			ErrorCode:    "validation",
			ErrorMessage: "protocol is required",
		},
	})
	defer cleanup()

	accepted, err := client.RequestKeygen(context.Background(), KeygenRequest{
		Protocol:  sdkprotocol.ProtocolTypeECDSA,
		Threshold: 1,
		WalletID:  "wallet-1",
		Participants: []KeygenParticipant{
			{ID: "p1", IdentityPublicKey: []byte("pub-1")},
			{ID: "p2", IdentityPublicKey: []byte("pub-2")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted || accepted.SessionID != "sess_keygen" || accepted.ExpiresAt == "" {
		t.Fatalf("unexpected accepted response: %+v", accepted)
	}

	_, err = client.RequestSign(context.Background(), SignRequest{
		Protocol:     sdkprotocol.ProtocolTypeECDSA,
		Threshold:    1,
		WalletID:     "wallet-1",
		SigningInput: []byte("message"),
		Participants: []SignParticipant{
			{ID: "p1", IdentityPublicKey: []byte("pub-1")},
			{ID: "p2", IdentityPublicKey: []byte("pub-2")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "coordinator rejected request (validation): protocol is required") {
		t.Fatalf("unexpected sign error: %v", err)
	}
}

func TestGRPCClientWaitSessionResultMapsKeygenAndSignature(t *testing.T) {
	signature := []byte("signature")
	recovery := []byte("recovery")
	r := []byte("r")
	s := []byte("s")
	signedInput := []byte("message")
	publicKey := []byte("public-key")
	client, cleanup := newTestGRPCClient(t, &fakeCoordinatorServer{
		results: map[string]*coordinatorv1.SessionResult{
			"sess_keygen": {
				Completed:    true,
				SessionId:    "sess_keygen",
				KeyId:        "wallet-1",
				PublicKeyHex: hex.EncodeToString(publicKey),
			},
			"sess_sign": {
				Completed:            true,
				SessionId:            "sess_sign",
				KeyId:                "wallet-1",
				PublicKeyHex:         hex.EncodeToString(publicKey),
				SignatureHex:         hex.EncodeToString(signature),
				SignatureRecoveryHex: hex.EncodeToString(recovery),
				RHex:                 hex.EncodeToString(r),
				SHex:                 hex.EncodeToString(s),
				SignedInputHex:       hex.EncodeToString(signedInput),
			},
		},
	})
	defer cleanup()

	keygenResult, err := client.WaitSessionResult(context.Background(), "sess_keygen")
	if err != nil {
		t.Fatal(err)
	}
	if keygenResult.KeyShare == nil || keygenResult.KeyShare.KeyID != "wallet-1" || string(keygenResult.KeyShare.PublicKey) != string(publicKey) {
		t.Fatalf("unexpected keygen result: %+v", keygenResult)
	}

	signResult, err := client.WaitSessionResult(context.Background(), "sess_sign")
	if err != nil {
		t.Fatal(err)
	}
	if signResult.Signature == nil || string(signResult.Signature.Signature) != string(signature) || string(signResult.Signature.PublicKey) != string(publicKey) {
		t.Fatalf("unexpected sign result: %+v", signResult)
	}
}
