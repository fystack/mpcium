// Needs nodes built with -tags dkls: creates a wallet, signs with the master and a child key, verifies both.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	clientID := flag.String("client-id", "example-dkls", "Client ID used to scope result routing")
	pathFlag := flag.String("path", "1,5", "Non-hardened child indices to derive, comma separated")
	timeout := flag.Duration("timeout", 60*time.Second, "How long to wait for each result")
	flag.Parse()

	config.InitViperConfig("")
	logger.Init("development", false)

	path, err := parsePath(*pathFlag)
	if err != nil {
		logger.Fatal("Invalid --path", err)
	}

	natsConn, err := nats.Connect(viper.GetString("nats.url"))
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	signer, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{
		KeyPath: "./event_initiator.key",
	})
	if err != nil {
		logger.Fatal("Failed to create signer", err)
	}
	mpcClient := client.NewMPCClient(client.Options{NatsConn: natsConn, Signer: signer, ClientID: *clientID})

	walletID := uuid.New().String()
	keys := make(chan event.KeygenResultEvent, 1)
	sigs := make(chan event.SigningResultEvent, 2)

	if err := mpcClient.OnWalletCreationResult(func(evt event.KeygenResultEvent) {
		// A dkls23 request also yields the tss-lib result; only the DKLs23 one carries DKLSPubKey.
		if evt.WalletID == walletID && (evt.ResultType != event.ResultTypeSuccess || len(evt.DKLSPubKey) > 0) {
			keys <- evt
		}
	}); err != nil {
		logger.Fatal("Failed to subscribe to wallet results", err)
	}
	if err := mpcClient.OnSignResult(func(evt event.SigningResultEvent) { sigs <- evt }); err != nil {
		logger.Fatal("Failed to subscribe to signing results", err)
	}

	fmt.Printf("Creating DKLs23 wallet %s ...\n", walletID)
	if err := mpcClient.CreateWalletWithProtocol(walletID, types.ProtocolDkls23, nil); err != nil {
		logger.Fatal("CreateWalletWithProtocol failed", err)
	}

	var keygen event.KeygenResultEvent
	select {
	case keygen = <-keys:
	case <-time.After(*timeout):
		fail("timed out waiting for the keygen result")
	}
	if keygen.ResultType != event.ResultTypeSuccess {
		fail("keygen failed: " + keygen.ErrorReason)
	}
	fmt.Printf("Public key (X||Y): %x\nChain code:        %x\n", keygen.DKLSPubKey, keygen.DKLSChainCode)

	masterPub, err := parseXY(keygen.DKLSPubKey)
	if err != nil {
		fail(err.Error())
	}
	childPub, err := deriveChild(masterPub, keygen.DKLSChainCode, path)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("Child public key at %v: %x\n", path, childPub.SerializeCompressed())

	hash := sha256.Sum256([]byte("hello dkls23"))
	for _, tc := range []struct {
		label string
		path  []uint32
		pub   *btcec.PublicKey
	}{
		{"master key", nil, masterPub},
		{"child key " + *pathFlag, path, childPub},
	} {
		txID := uuid.New().String()
		err := mpcClient.SignTransaction(&types.SignTxMessage{
			KeyType:             types.KeyTypeSecp256k1,
			Protocol:            types.ProtocolDkls23,
			WalletID:            walletID,
			NetworkInternalCode: "example",
			TxID:                txID,
			Tx:                  hash[:], // DKLs23 signs a 32-byte hash
			DerivationPath:      tc.path,
		})
		if err != nil {
			fail("SignTransaction failed: " + err.Error())
		}

		select {
		case res := <-sigs:
			if res.ResultType != event.ResultTypeSuccess {
				fail("signing failed: " + res.ErrorReason)
			}
			ok := verify(res, hash[:], tc.pub)
			fmt.Printf("Signed with %-14s r=%x s=%x recovery=%d verified=%v\n", tc.label, res.R, res.S, res.SignatureRecovery[0], ok)
			if !ok {
				os.Exit(1)
			}
		case <-time.After(*timeout):
			fail("timed out waiting for the signing result")
		}
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

func parsePath(s string) ([]uint32, error) {
	var path []uint32
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil || n >= 0x80000000 {
			return nil, fmt.Errorf("%q is not a non-hardened index", part)
		}
		path = append(path, uint32(n))
	}
	return path, nil
}

func parseXY(xy []byte) (*btcec.PublicKey, error) {
	if len(xy) != 64 {
		return nil, fmt.Errorf("public key must be 64 bytes (X||Y), got %d", len(xy))
	}
	return btcec.ParsePubKey(append([]byte{0x04}, xy...))
}

// deriveChild computes the BIP-32 public child key, so child addresses are known without the nodes.
func deriveChild(pub *btcec.PublicKey, chainCode []byte, path []uint32) (*btcec.PublicKey, error) {
	for _, index := range path {
		mac := hmac.New(sha512.New, chainCode)
		mac.Write(pub.SerializeCompressed())
		mac.Write(binary.BigEndian.AppendUint32(nil, index))
		sum := mac.Sum(nil)

		var tweak btcec.ModNScalar
		if tweak.SetByteSlice(sum[:32]) {
			return nil, fmt.Errorf("invalid tweak at index %d", index)
		}
		var tweakPoint, parent, child btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&tweak, &tweakPoint)
		pub.AsJacobian(&parent)
		btcec.AddNonConst(&tweakPoint, &parent, &child)
		child.ToAffine()
		pub = btcec.NewPublicKey(&child.X, &child.Y)
		chainCode = sum[32:]
	}
	return pub, nil
}

func verify(res event.SigningResultEvent, hash []byte, pub *btcec.PublicKey) bool {
	var r, s btcec.ModNScalar
	r.SetByteSlice(res.R)
	s.SetByteSlice(res.S)
	if !btcecdsa.NewSignature(&r, &s).Verify(hash, pub) {
		return false
	}
	compact := append([]byte{27 + 4 + res.SignatureRecovery[0]}, append(res.R, res.S...)...)
	recovered, _, err := btcecdsa.RecoverCompact(compact, hash)
	return err == nil && recovered.IsEqual(pub)
}
