package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	tsscrypto "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium/pkg/ckdutil"
	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"golang.org/x/crypto/sha3"
)

const (
	// Solana derivation path: m/44'/501'/x'/0'
	solPurpose  = 44  // BIP44
	solCoinType = 501 // Solana
	solChange   = 0   // External chain

	// Number of addresses to derive; change this to derive more or fewer addresses.
	addressCount = 2
)

type DerivedAddress struct {
	Index          uint32
	DerivationPath []uint32
	PublicKey      []byte
	Address        string
}

func main() {
	fmt.Println("========================================")
	fmt.Println("   MPC HD Wallet - Solana (EdDSA) Example")
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
				masterPubKey = evt.EDDSAPubKey // 32 bytes for Ed25519
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
	fmt.Printf("   Public Key (32 bytes): %s...\n", hex.EncodeToString(masterPubKey)[:40])
	fmt.Println()

	// Step 2: Derive addresses from master public key (client-side!)
	fmt.Println("Step 2: Deriving Solana addresses from master public key...")
	fmt.Println("   (This is done CLIENT-SIDE, no MPC needed!)")
	fmt.Println()

	chainCodeHex := viper.GetString("chain_code")
	if chainCodeHex == "" {
		logger.Fatal("chain_code not found in config", fmt.Errorf("required for HD derivation"))
	}

	addresses := make([]*DerivedAddress, addressCount)
	for i := 0; i < addressCount; i++ {
		childIndex := uint32(i)
		path := []uint32{solPurpose, solCoinType, childIndex, solChange}

		// Derive child public key from master (NO MPC!)
		childPubKey, err := deriveChildPublicKeyEd25519(masterPubKey, chainCodeHex, path)
		if err != nil {
			logger.Fatal("Failed to derive child public key", err)
		}

		// Optional sanity check: compare with tss-lib CKD to ensure parity.
		if tssChild, err := deriveChildPublicKeyEd25519ViaTSS(masterPubKey, chainCodeHex, path, masterWalletID); err != nil {
			logger.Warn("Unable to compare with tss-lib CKD", "error", err)
		} else if !slices.Equal(childPubKey, tssChild) {
			logger.Warn("Derived child pubkey mismatch between local CKD and tss-lib", "path", path)
		} else {
			logger.Info("Derived child pubkey matches tss-lib", "path", path)
		}

		address := deriveSolanaAddress(childPubKey)

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
		fmt.Printf("  Derivation Path:  m/%d/%d/%d/%d\n",
			addr.DerivationPath[0], addr.DerivationPath[1],
			addr.DerivationPath[2], addr.DerivationPath[3])
		fmt.Printf("  Public Key:       %s...\n", hex.EncodeToString(addr.PublicKey)[:40])
		fmt.Printf("  Solana Address:   %s\n", addr.Address)
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

		// Hash the message to 32 bytes (required for EdDSA signing)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(txMsg))
		txHash := hash.Sum(nil)

		txID := uuid.New().String()

		resultCh := make(chan event.SigningResultEvent, 1)

		mu.Lock()
		resultChans[txID] = resultCh
		mu.Unlock()

		logger.Info("Derivation path", "path", addr.DerivationPath)

		signTxMsg := &types.SignTxMessage{
			WalletID:            masterWalletID,
			TxID:                txID,
			Tx:                  txHash,
			KeyType:             types.KeyTypeEd25519,
			NetworkInternalCode: "solana-devnet",
			DerivationPath:      addr.DerivationPath,
		}

		fmt.Printf("📝 Address %d: Signing with path m/%d/%d/%d/%d...\n",
			addr.Index+1,
			addr.DerivationPath[0], addr.DerivationPath[1],
			addr.DerivationPath[2], addr.DerivationPath[3])

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
		fmt.Printf("   Signature: %s\n", hex.EncodeToString(result.Signature))

		valid := verifySignatureEd25519(txHash, addr.PublicKey, result.Signature)
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
	fmt.Printf("Addresses derived:  %d\n", len(addresses))
	fmt.Printf("Signatures success: %d\n", successCount)
	fmt.Printf("Signatures failed:  %d\n", len(addresses)-successCount)
	fmt.Printf("Verified locally:   %d\n", verifiedCount)
	fmt.Println()

	if successCount == len(addresses) {
		fmt.Println("✅ All transactions signed successfully!")
		fmt.Println()
		fmt.Println("📚 What happened:")
		fmt.Println("   1. Created ONE master MPC wallet")
		fmt.Printf("   2. Derived %d Solana addresses CLIENT-SIDE (no MPC)\n", len(addresses))
		fmt.Println("   3. MPC derived child keys during signing")
		fmt.Println("   4. Verified signatures locally against derived keys")
	}

	fmt.Println("\nDone!")

	// Keep running
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}

// deriveChildPublicKeyEd25519 derives Ed25519 child key CLIENT-SIDE (no MPC)
func deriveChildPublicKeyEd25519(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) == 0 {
		return nil, fmt.Errorf("master public key is empty")
	}

	derivedBytes, err := ckdutil.DeriveEd25519ChildCompressed(masterPubKey, chainCodeHex, path)
	if err != nil {
		return nil, err
	}

	if len(derivedBytes) != 32 {
		return nil, fmt.Errorf("unexpected derived pubkey length: %d", len(derivedBytes))
	}

	return derivedBytes, nil
}

func deriveSolanaAddress(pubKey []byte) string {
	if len(pubKey) != 32 {
		logger.Error("Invalid pubkey length for Solana", fmt.Errorf("got %d", len(pubKey)))
		return ""
	}

	// Solana address is just base58-encoded public key
	address := base58.Encode(pubKey)
	return address
}

func verifySignatureEd25519(message, pubKey, signature []byte) bool {
	if len(pubKey) == 0 || len(signature) == 0 {
		return false
	}

	decodedPub, err := encoding.DecodeEDDSAPubKey(pubKey)
	if err != nil {
		return false
	}

	parsedSig, err := edwards.ParseSignature(signature)
	if err != nil {
		return false
	}

	return edwards.Verify(decodedPub, message, parsedSig.R, parsedSig.S)
}

// deriveChildPublicKeyEd25519ViaTSS mirrors the MPC node CKD path to validate parity.
func deriveChildPublicKeyEd25519ViaTSS(masterPubKey []byte, chainCodeHex string, path []uint32, walletID string) ([]byte, error) {
	pubKey, err := encoding.DecodeEDDSAPubKey(masterPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode master pubkey: %w", err)
	}

	masterPoint, err := tsscrypto.NewECPoint(tss.Edwards(), pubKey.X, pubKey.Y)
	if err != nil {
		return nil, fmt.Errorf("build EC point from master pubkey: %w", err)
	}

	ckd, err := mpc.NewCKDFromHex(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("init CKD: %w", err)
	}

	_, childKey, err := ckd.Derive(walletID, masterPoint, path, tss.Edwards())
	if err != nil {
		return nil, fmt.Errorf("derive child key for path %v: %w", path, err)
	}

	childPub := edwards.PublicKey{
		Curve: tss.Edwards(),
		X:     childKey.PublicKey.X(),
		Y:     childKey.PublicKey.Y(),
	}

	return childPub.SerializeCompressed(), nil
}
