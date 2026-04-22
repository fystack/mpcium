package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/fystack/mpcium/pkg/coordinatorclient"
	"github.com/google/uuid"
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
	}

	walletID := "wallet_" + uuid.New().String()
	runKeygen(client, participants, walletID)
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func runKeygen(client *coordinatorclient.Client, participants []coordinatorclient.KeygenParticipant, walletID string) {
	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := client.RequestKeygen(requestCtx, coordinatorclient.KeygenRequest{
		Threshold:    1,
		WalletID:     walletID,
		Participants: participants,
	})
	cancelRequest()
	if err != nil {
		log.Fatalf("request keygen: %v (verify both cosigners are online and publishing real presence)", err)
	}
	acceptedAt := time.Now()

	resultCtx, cancelResult := context.WithTimeout(context.Background(), 2*time.Minute)
	result, err := client.WaitSessionResult(resultCtx, resp.SessionID)
	cancelResult()
	if err != nil {
		log.Fatalf("wait session result: %v (check both cosigners are running and session events are flowing)", err)
	}
	if result == nil || result.Keygen == nil {
		fmt.Printf("session_id=%s result=empty wait_seconds=%.3f\n", resp.SessionID, time.Since(acceptedAt).Seconds())
		return
	}

	fmt.Printf("key_id=%s session_id=%s wait_seconds=%.3f\n", result.Keygen.KeyID, resp.SessionID, time.Since(acceptedAt).Seconds())
	if len(result.Keygen.ECDSAPubKey) > 0 {
		fmt.Printf("ecdsa_pubkey_hex=%s\n", hex.EncodeToString(result.Keygen.ECDSAPubKey))
	}
	if len(result.Keygen.EDDSAPubKey) > 0 {
		fmt.Printf("eddsa_pubkey_hex=%s\n", hex.EncodeToString(result.Keygen.EDDSAPubKey))
	}
}
