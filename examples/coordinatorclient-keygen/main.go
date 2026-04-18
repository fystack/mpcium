package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/fystack/mpcium/pkg/coordinatorclient"
	"github.com/google/uuid"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

func main() {
	client, err := coordinatorclient.New(coordinatorclient.Config{
		NATSURL: "nats://127.0.0.1:4222",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("create coordinator client: %v", err)
	}
	defer client.Close()

	participants := []coordinatorclient.KeygenParticipant{
		{
			ID:                "peer-node-01",
			IdentityPublicKey: mustDecodeHex("56a47a1103b610d6c85bf23ddb1f78ff6404f7c6f170d46441a268e105873cc4"),
		},
		{
			ID:                "peer-node-02",
			IdentityPublicKey: mustDecodeHex("d9034dd84e0dd10a57d6a09a8267b217051d5f121ff52fca66c2b485be16ae02"),
		},
		{
			ID:                "mobile-sample-01",
			IdentityPublicKey: mustDecodeHex("0c67697e3142c1c87dd8fa034fdfece14fc8ba00145bc0f123d6cd8bd33640e2"),
		},
	}

	walletID := "wallet_" + uuid.New().String()
	runKeygenForProtocol(client, participants, walletID, sdkprotocol.ProtocolTypeECDSA)
	runKeygenForProtocol(client, participants, walletID, sdkprotocol.ProtocolTypeEdDSA)
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func runKeygenForProtocol(client *coordinatorclient.Client, participants []coordinatorclient.KeygenParticipant, walletID string, protocol sdkprotocol.ProtocolType) {
	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := client.RequestKeygen(requestCtx, coordinatorclient.KeygenRequest{
		Protocol:     protocol,
		Threshold:    1,
		WalletID:     walletID,
		Participants: participants,
	})
	cancelRequest()
	if err != nil {
		log.Fatalf("request keygen (%s): %v (verify both cosigners are online and publishing real presence)", protocol, err)
	}
	acceptedAt := time.Now()

	resultCtx, cancelResult := context.WithTimeout(context.Background(), 2*time.Minute)
	result, err := client.WaitSessionResult(resultCtx, resp.SessionID)
	cancelResult()
	if err != nil {
		log.Fatalf("wait session result (%s): %v (check both cosigners are running and session events are flowing)", protocol, err)
	}
	if result == nil {
		fmt.Printf("protocol=%s session_id=%s result=empty wait_seconds=%.3f\n", protocol, resp.SessionID, time.Since(acceptedAt).Seconds())
		return
	}
	fmt.Printf("protocol=%s key_id=%s session_id=%s wait_seconds=%.3f\n", protocol, result.KeyShare.KeyID, resp.SessionID, time.Since(acceptedAt).Seconds())
	if result.KeyShare != nil {
		fmt.Printf("public_key_hex=%s\n", hex.EncodeToString(result.KeyShare.PublicKey))
	}
}
