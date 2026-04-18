package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium/pkg/coordinatorclient"
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

	participants := []coordinatorclient.SignParticipant{
		{
			ID:                "peer-node-01",
			IdentityPublicKey: mustDecodeHex("56a47a1103b610d6c85bf23ddb1f78ff6404f7c6f170d46441a268e105873cc4"),
		},
		{
			ID:                "mobile-sample-01",
			IdentityPublicKey: mustDecodeHex("0c67697e3142c1c87dd8fa034fdfece14fc8ba00145bc0f123d6cd8bd33640e2"),
		},
	}

	walletID := "wallet_f8029c22-a222-4828-b135-8aacc021d716"
	message := []byte("deadbeef")
	protocol := sdkprotocol.ProtocolTypeEdDSA

	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := client.RequestSign(requestCtx, coordinatorclient.SignRequest{
		Protocol:     protocol,
		Threshold:    1,
		WalletID:     walletID,
		SigningInput: message,
		Participants: participants,
	})
	cancelRequest()
	if err != nil {
		log.Fatalf("request sign: %v (verify both cosigners are online and wallet ID exists for this protocol)", err)
	}
	acceptedAt := time.Now()

	resultCtx, cancelResult := context.WithTimeout(context.Background(), 2*time.Minute)
	result, err := client.WaitSessionResult(resultCtx, resp.SessionID)
	cancelResult()
	if err != nil {
		log.Fatalf("wait session result: %v (check both cosigners are running and session events are flowing)", err)
	}
	if result == nil || result.Signature == nil {
		fmt.Printf("session_id=%s result=empty wait_seconds=%.3f\n", resp.SessionID, time.Since(acceptedAt).Seconds())
		return
	}

	sig := result.Signature
	fmt.Printf("session_id=%s key_id=%s wait_seconds=%.3f\n", resp.SessionID, sig.KeyID, time.Since(acceptedAt).Seconds())
	fmt.Printf("signature_hex=%s\n", hex.EncodeToString(sig.Signature))
	if len(sig.R) > 0 || len(sig.S) > 0 {
		fmt.Printf("r_hex=%s\n", hex.EncodeToString(sig.R))
		fmt.Printf("s_hex=%s\n", hex.EncodeToString(sig.S))
	}
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func mustPublicKeyFromPrivateHex(privateKeyHex string) []byte {
	privateRaw := mustDecodeHex(privateKeyHex)
	var private ed25519.PrivateKey
	switch len(privateRaw) {
	case ed25519.PrivateKeySize:
		private = ed25519.PrivateKey(privateRaw)
	case ed25519.SeedSize:
		private = ed25519.NewKeyFromSeed(privateRaw)
	default:
		panic(fmt.Sprintf("invalid ed25519 private key length: %d", len(privateRaw)))
	}
	public := private.Public().(ed25519.PublicKey)
	return append([]byte(nil), public...)
}
