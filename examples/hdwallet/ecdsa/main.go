package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fystack/mpcium/pkg/ckdutil"
	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"golang.org/x/crypto/sha3"
)

const (
	// Ethereum derivation path: m/44/60/0/0/x
	ethPurpose  = 44 // BIP44
	ethCoinType = 60 // Ethereum
	ethAccount  = 0  // Account 0
	ethChange   = 0  // External chain
)

type DerivedAddress struct {
	Index          uint32
	DerivationPath []uint32
	PublicKey      []byte
	Address        string
}

func main() {
	fmt.Println("========================================")
	fmt.Println("   MPC HD Wallet - Ethereum (ECDSA) Example")
	fmt.Println("========================================")
	fmt.Println()

	const environment = "dev"
	config.InitViperConfig("")
	logger.Init(environment, true)

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}

	if !slices.Contains(
		[]string{
			string(types.EventInitiatorKeyTypeEd25519),
			string(types.EventInitiatorKeyTypeP256),
		},
		algorithm,
	) {
		logger.Fatal(
			fmt.Sprintf(
				"invalid algorithm: %s. Must be %s or %s",
				algorithm,
				types.EventInitiatorKeyTypeEd25519,
				types.EventInitiatorKeyTypeP256,
			),
			nil,
		)
	}

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	localSigner, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{
		KeyPath: "./event_initiator.key",
	})
	if err != nil {
		logger.Fatal("Failed to create local signer", err)
	}

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		Signer:   localSigner,
	})

	// Step 1: Generate ONE master wallet
	fmt.Println("Step 1: Generating master MPC wallet...")
	fmt.Println()

	masterWalletID := uuid.New().String()
	var masterPubKey []byte
	var wg sync.WaitGroup

	// Listen for wallet creation result
	wg.Add(1)
	err = mpcClient.OnWalletCreationResult(func(evt event.KeygenResultEvent) {
		if evt.WalletID == masterWalletID {
			if evt.ResultType == event.ResultTypeError {
				logger.Error("Master wallet creation failed",
					fmt.Errorf("%s: %s", evt.ErrorCode, evt.ErrorReason),
					"walletID", evt.WalletID,
				)
			} else {
				masterPubKey = evt.ECDSAPubKey // 64 bytes: X || Y
				logger.Info("Master wallet created successfully",
					"walletID", evt.WalletID,
					"pubkey_length", len(masterPubKey),
				)
			}
			wg.Done()
		}
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to wallet creation results", err)
	}

	// Create master wallet
	if err := mpcClient.CreateWallet(masterWalletID); err != nil {
		logger.Fatal("Failed to create master wallet", err)
	}

	// Wait for master wallet creation
	wg.Wait()

	if len(masterPubKey) == 0 {
		fmt.Println("\n❌ Master wallet creation failed. Exiting.")
		os.Exit(1)
	}

	fmt.Println("\n✅ Master wallet created successfully!")
	fmt.Printf("   Wallet ID: %s\n", masterWalletID)
	fmt.Printf("   Public Key (64 bytes): %s...\n", hex.EncodeToString(masterPubKey)[:40])
	fmt.Println()

	// Step 2: Derive 2 addresses from master public key (client-side!)
	fmt.Println("Step 2: Deriving addresses from master public key...")
	fmt.Println("   (This is done CLIENT-SIDE, no MPC needed!)")
	fmt.Println()

	chainCodeHex := viper.GetString("chain_code")
	if chainCodeHex == "" {
		logger.Fatal("chain_code not found in config", fmt.Errorf("required for HD derivation"))
	}

	addresses := make([]*DerivedAddress, 2)
	for i := 0; i < 2; i++ {
		childIndex := uint32(i)
		path := []uint32{ethPurpose, ethCoinType, ethAccount, ethChange, childIndex}

		// Derive child public key from master (NO MPC!)
		childPubKey, err := deriveChildPublicKey(masterPubKey, chainCodeHex, path)
		if err != nil {
			logger.Fatal("Failed to derive child public key", err)
		}

		address := deriveEthereumAddress(childPubKey)

		addresses[i] = &DerivedAddress{
			Index:          childIndex,
			DerivationPath: path,
			PublicKey:      childPubKey,
			Address:        address,
		}
	}

	// Display derived addresses
	fmt.Println("========================================")
	fmt.Println("   Derived Addresses (from Master)")
	fmt.Println("========================================")
	fmt.Println()

	for _, addr := range addresses {
		fmt.Printf("Address %d:\n", addr.Index+1)
		fmt.Printf("  Derivation Path:  m/%d/%d/%d/%d/%d\n",
			addr.DerivationPath[0], addr.DerivationPath[1], addr.DerivationPath[2],
			addr.DerivationPath[3], addr.DerivationPath[4])
		fmt.Printf("  Public Key:       %s...\n", hex.EncodeToString(addr.PublicKey)[:40])
		fmt.Printf("  Ethereum Address: %s\n", addr.Address)
		fmt.Println()
	}

	// Step 3: Sequential signing & verification
	fmt.Println("========================================")
	fmt.Println("   Sequential Signing & Verification")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Signing each derived address sequentially and verifying locally.")
	fmt.Println()

	var mu sync.Mutex
	resultChans := make(map[string]chan event.SigningResultEvent)

	err = mpcClient.OnSignResult(func(evt event.SigningResultEvent) {
		mu.Lock()
		ch, ok := resultChans[evt.TxID]
		mu.Unlock()

		if ok {
			ch <- evt
		}
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to signing results", err)
	}

	successCount := 0
	verifiedCount := 0

	for _, addr := range addresses {
		txMsg := fmt.Sprintf("Sequential signing from address %d (%s)", addr.Index+1, addr.Address)

		// Hash the message to 32 bytes (required for ECDSA signing)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(txMsg))
		txHash := hash.Sum(nil)

		txID := uuid.New().String()

		resultCh := make(chan event.SigningResultEvent, 1)

		mu.Lock()
		resultChans[txID] = resultCh
		mu.Unlock()

		logger.Info("Derivaition path", "path", addr.DerivationPath)

		signTxMsg := &types.SignTxMessage{
			WalletID:            masterWalletID,
			TxID:                txID,
			Tx:                  txHash,
			KeyType:             types.KeyTypeSecp256k1,
			NetworkInternalCode: "ethereum-mainnet",
			DerivationPath:      addr.DerivationPath,
		}

		fmt.Printf("📝 Address %d: Signing with path m/%d/%d/%d/%d/%d...\n",
			addr.Index+1,
			addr.DerivationPath[0], addr.DerivationPath[1], addr.DerivationPath[2],
			addr.DerivationPath[3], addr.DerivationPath[4])

		if err := mpcClient.SignTransaction(signTxMsg); err != nil {
			logger.Error("Failed to initiate signing", err)
			mu.Lock()
			delete(resultChans, txID)
			mu.Unlock()
			close(resultCh)
			continue
		}

		var result event.SigningResultEvent
		select {
		case result = <-resultCh:
			mu.Lock()
			delete(resultChans, txID)
			mu.Unlock()
			close(resultCh)
		case <-time.After(45 * time.Second):
			fmt.Printf("❌ Address %d: Timed out waiting for signing result\n", addr.Index+1)
			mu.Lock()
			delete(resultChans, txID)
			mu.Unlock()
			close(resultCh)
			continue
		}

		if result.ResultType == event.ResultTypeError {
			fmt.Printf("❌ Address %d: Signing failed - %s (%s)\n",
				addr.Index+1, result.ErrorReason, result.ErrorCode)
			continue
		}

		successCount++

		fmt.Printf("✅ Address %d: Signed successfully\n", addr.Index+1)
		fmt.Printf("   R: %s\n", hex.EncodeToString(result.R))
		fmt.Printf("   S: %s\n", hex.EncodeToString(result.S))
		fmt.Printf("   V: %s\n", hex.EncodeToString(result.SignatureRecovery))

		valid, err := verifySignature(txHash, addr.PublicKey, result.R, result.S)
		if err != nil {
			fmt.Printf("   ⚠️  Unable to verify signature: %v\n", err)
			continue
		}

		if valid {
			verifiedCount++
			fmt.Println("   🔐 Signature verified against derived public key.")
		} else {
			fmt.Println("   ⚠️  Signature verification failed.")
		}
	}

	// Summary
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("   Summary")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("Master Wallet ID:   %s\n", masterWalletID)
	fmt.Printf("Addresses derived:  2\n")
	fmt.Printf("Signatures success: %d\n", successCount)
	fmt.Printf("Signatures failed:  %d\n", len(addresses)-successCount)
	fmt.Printf("Verified locally:   %d\n", verifiedCount)
	fmt.Println()

	if successCount == 2 {
		fmt.Println("✅ All transactions signed successfully!")
		fmt.Println()
		fmt.Println("📚 What happened:")
		fmt.Println("   1. Created ONE master MPC wallet")
		fmt.Println("   2. Derived 2 addresses CLIENT-SIDE (no MPC)")
		fmt.Println("   3. MPC derived child keys during signing")
		fmt.Println("   4. Verified signatures locally against derived keys")
	}

	fmt.Println("\nDone!")
}

// deriveChildPublicKey derives child key CLIENT-SIDE (no MPC) using ckdutil.
func deriveChildPublicKey(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) != 64 {
		return nil, fmt.Errorf("invalid master key length: %d", len(masterPubKey))
	}

	uncompressed := append([]byte{0x04}, masterPubKey...)
	masterPub, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("parse master pubkey: %w", err)
	}

	childCompressed, err := ckdutil.DeriveSecp256k1ChildCompressed(
		masterPub.SerializeCompressed(),
		chainCodeHex,
		path,
	)
	if err != nil {
		return nil, fmt.Errorf("derive child pubkey: %w", err)
	}

	childPub, err := btcec.ParsePubKey(childCompressed)
	if err != nil {
		return nil, fmt.Errorf("parse child pubkey: %w", err)
	}

	return serializeUncompressed(childPub), nil
}

func deriveEthereumAddress(pubKey []byte) string {
	if len(pubKey) != 64 {
		logger.Error("Invalid pubkey length", fmt.Errorf("got %d", len(pubKey)))
		return ""
	}

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKey)
	hashBytes := hash.Sum(nil)

	addressBytes := hashBytes[len(hashBytes)-20:]
	address := "0x" + hex.EncodeToString(addressBytes)

	return toChecksumAddress(address)
}

func toChecksumAddress(address string) string {
	address = strings.ToLower(strings.TrimPrefix(address, "0x"))

	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(address))
	hashBytes := hash.Sum(nil)

	result := "0x"
	for i := 0; i < len(address); i++ {
		hashByte := hashBytes[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte = hashByte & 0xf
		}

		if hashByte >= 8 {
			result += strings.ToUpper(string(address[i]))
		} else {
			result += string(address[i])
		}
	}

	return result
}

func verifySignature(message, pubKey, rBytes, sBytes []byte) (bool, error) {
	if len(pubKey) != 64 {
		return false, fmt.Errorf("invalid public key length: %d", len(pubKey))
	}

	if len(rBytes) == 0 || len(sBytes) == 0 {
		return false, fmt.Errorf("signature components missing")
	}

	curve := btcec.S256()
	x := new(big.Int).SetBytes(pubKey[:32])
	y := new(big.Int).SetBytes(pubKey[32:])

	if !curve.IsOnCurve(x, y) {
		return false, fmt.Errorf("public key not on secp256k1 curve")
	}

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false, fmt.Errorf("invalid signature values")
	}

	ok := ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, message, r, s)
	return ok, nil
}

func serializeUncompressed(pub *btcec.PublicKey) []byte {
	out := make([]byte, 64)
	xBytes := pub.X().Bytes()
	yBytes := pub.Y().Bytes()
	copy(out[32-len(xBytes):32], xBytes)
	copy(out[64-len(yBytes):], yBytes)
	return out
}
