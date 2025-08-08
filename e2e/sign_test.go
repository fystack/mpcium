package e2e

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ErrInvalidSig = errors.New("invalid signature")

// ComposeSignature composes a signature from v, r, s components
func ComposeSignature(v, r, s []byte) ([]byte, error) {
	V := v[0]
	if !validateSignatureValues(
		V,
		new(big.Int).SetBytes(r),
		new(big.Int).SetBytes(s), false) {
		return nil, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	return sig, nil
}

// validateSignatureValues verifies whether the signature values are valid
func validateSignatureValues(v uint8, r, s *big.Int, homestead bool) bool {
	if r.Cmp(big.NewInt(1)) < 0 || s.Cmp(big.NewInt(1)) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

func TestSigning(t *testing.T) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", true)

	// Comprehensive cleanup before starting tests
	t.Log("Performing pre-test cleanup...")
	suite.CleanupTestEnvironment(t)

	// Ensure cleanup happens even if test fails
	defer func() {
		t.Log("Performing post-test cleanup...")
		suite.Cleanup(t)
	}()

	// Setup infrastructure
	t.Run("Setup", func(t *testing.T) {
		// Run make clean first to ensure a clean build
		t.Log("Running make clean to ensure clean build...")
		err := suite.RunMakeClean()
		require.NoError(t, err, "Failed to run make clean")
		t.Log("make clean completed")

		t.Log("Starting setupInfrastructure...")
		suite.SetupInfrastructure(t)
		t.Log("setupInfrastructure completed")

		t.Log("Starting setupTestNodes...")
		suite.SetupTestNodes(t)
		t.Log("setupTestNodes completed")

		// Load config after setup script runs
		err = suite.LoadConfig()
		require.NoError(t, err, "Failed to load config after setup")

		t.Log("Starting registerPeers...")
		suite.RegisterPeers(t)
		t.Log("registerPeers completed")

		t.Log("Starting setupMPCClient...")
		suite.SetupMPCClient(t)
		t.Log("setupMPCClient completed")

		t.Log("Starting startNodes...")
		suite.StartNodes(t)
		t.Log("startNodes completed")
	})

	// Test key generation first
	t.Run("KeyGenerationForSigning", func(t *testing.T) {
		testKeyGenerationForSigning(t, suite)
	})

	// Test signing with all nodes
	t.Run("SigningAllNodes", func(t *testing.T) {
		testSigningAllNodes(t, suite)
	})

	// // Test signing with one node offline
	// t.Run("SigningOneNodeOffline", func(t *testing.T) {
	// 	testSigningOneNodeOffline(t, suite)
	// })
}

func testKeyGenerationForSigning(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing key generation for signing tests...")

	// Ensure MPC client is initialized
	if suite.mpcClient == nil {
		t.Fatal("MPC client is not initialized. Make sure Setup subtest runs first.")
	}

	// Wait for all nodes to be ready before proceeding
	suite.WaitForNodesReady(t)

	// Generate 1 wallet ID for testing
	walletIDs := make([]string, 1)
	for i := 0; i < 1; i++ {
		walletIDs[i] = uuid.New().String()
		suite.walletIDs = append(suite.walletIDs, walletIDs[i])
	}

	t.Logf("Generated wallet IDs: %v", walletIDs)

	// Setup result listener
	err := suite.mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		t.Logf("Received keygen result for wallet %s: %s", result.WalletID, result.ResultType)
		suite.keygenResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Keygen failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Keygen succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup keygen result listener")

	// Add a small delay to ensure the result listener is fully set up
	time.Sleep(10 * time.Second)

	// Trigger key generation for all wallets
	for _, walletID := range walletIDs {
		t.Logf("Triggering key generation for wallet %s", walletID)

		err := suite.mpcClient.CreateWallet(walletID)
		require.NoError(t, err, "Failed to trigger key generation for wallet %s", walletID)

		// Small delay between requests to avoid overwhelming the system
		time.Sleep(500 * time.Millisecond)
	}

	// Wait for key generation to complete
	t.Log("Waiting for key generation to complete...")

	// Wait up to keygenTimeout for all results
	timeout := time.NewTimer(keygenTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Logf("Timeout waiting for keygen results. Received %d/%d results", len(suite.keygenResults), len(walletIDs))
			// Don't fail immediately, let's check what we got
			goto checkResults
		case <-ticker.C:
			t.Logf("Still waiting... Received %d/%d keygen results", len(suite.keygenResults), len(walletIDs))

			if len(suite.keygenResults) >= len(walletIDs) {
				goto checkResults
			}
		}
	}

checkResults:
	// Check that we got results for all wallets
	for _, walletID := range walletIDs {
		result, exists := suite.keygenResults[walletID]
		if !exists {
			t.Errorf("No keygen result received for wallet %s", walletID)
			continue
		}

		if result.ResultType == event.ResultTypeError {
			t.Errorf("Keygen failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Keygen succeeded for wallet %s", result.WalletID)
			assert.NotEmpty(t, result.ECDSAPubKey, "ECDSA public key should not be empty for wallet %s", walletID)
			assert.NotEmpty(t, result.EDDSAPubKey, "EdDSA public key should not be empty for wallet %s", walletID)
		}
	}

	t.Log("Key generation for signing tests completed")
}

func testSigningAllNodes(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing signing with all nodes online...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing. Make sure key generation ran first.")
	}

	// Setup a shared signing result listener for all signing tests
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received signing result for wallet %s (tx: %s): %s", result.WalletID, result.TxID, result.ResultType)
		// Use TxID as key to avoid conflicts between different signing operations
		signingResults[result.TxID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Signing failed for wallet %s (tx: %s): %s (%s)", result.WalletID, result.TxID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Signing succeeded for wallet %s (tx: %s)", result.WalletID, result.TxID)
		}
	})
	require.NoError(t, err, "Failed to setup signing result listener")

	// Wait for listener setup
	time.Sleep(2 * time.Second)

	// Test messages to sign
	testMessages := []string{
		"Hello, MPC World!",
		"Test message 2",
		"Test message 3",
	}

	for _, walletID := range suite.walletIDs {
		t.Logf("Testing signing for wallet %s", walletID)

		for i, message := range testMessages {
			t.Logf("Signing message %d: %s", i+1, message)

			// Test ECDSA signing
			t.Run(fmt.Sprintf("ECDSA_%s_%d", walletID, i), func(t *testing.T) {
				testECDSASigningWithSharedListener(t, suite, walletID, message, signingResults)
			})

			// Test EdDSA signing
			t.Run(fmt.Sprintf("EdDSA_%s_%d", walletID, i), func(t *testing.T) {
				testEdDSASigningWithSharedListener(t, suite, walletID, message, signingResults)
			})
		}
	}

	t.Log("Signing with all nodes completed")
}

func testSigningOneNodeOffline(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing signing with one node offline...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing. Make sure key generation ran first.")
	}

	// Stop one node (node 2)
	nodeToStop := 2
	t.Logf("Stopping node %d to test fault tolerance...", nodeToStop)

	if nodeToStop < len(suite.mpciumProcesses) && suite.mpciumProcesses[nodeToStop] != nil {
		err := suite.mpciumProcesses[nodeToStop].Process.Kill()
		if err != nil {
			t.Logf("Failed to stop node %d: %v", nodeToStop, err)
		} else {
			t.Logf("Successfully stopped node %d", nodeToStop)
			// Mark as stopped
			suite.mpciumProcesses[nodeToStop] = nil
		}
	}

	// Wait a bit for the network to adjust
	time.Sleep(5 * time.Second)

	// Test signing with reduced nodes
	walletID := suite.walletIDs[0] // Use first wallet
	message := "Fault tolerance test message"

	t.Logf("Testing signing with wallet %s and one node offline", walletID)

	// Test ECDSA signing with one node offline
	t.Run("ECDSA_OneNodeOffline", func(t *testing.T) {
		testECDSASigning(t, suite, walletID, message)
	})

	// Test EdDSA signing with one node offline
	t.Run("EdDSA_OneNodeOffline", func(t *testing.T) {
		testEdDSASigning(t, suite, walletID, message)
	})

	t.Log("Signing with one node offline completed")
}

func testECDSASigning(t *testing.T, suite *E2ETestSuite, walletID, message string) {
	t.Logf("Testing ECDSA signing for wallet %s with message: %s", walletID, message)

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received ECDSA signing result for wallet %s: %s", result.WalletID, result.ResultType)
		signingResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("ECDSA signing failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("ECDSA signing succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup ECDSA signing result listener")

	// Wait for listener setup
	time.Sleep(1 * time.Second)

	// Create a signing transaction message
	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  []byte(message),
		KeyType:             types.KeyTypeSecp256k1,
		NetworkInternalCode: "test",
	}

	// Trigger ECDSA signing
	err = suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger ECDSA signing for wallet %s", walletID)

	// Wait for signing result
	timeout := time.NewTimer(signingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for ECDSA signing result for wallet %s", walletID)
		case <-ticker.C:
			if result, exists := signingResults[txID]; exists {
				logger.Info("Received ECDSA signing result for wallet", "result", result)
				if result.ResultType == event.ResultTypeError {
					t.Errorf("ECDSA signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("ECDSA signing succeeded for wallet %s", walletID)
					assert.NotEmpty(t, result.R, "ECDSA R value should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.S, "ECDSA S value should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.SignatureRecovery, "ECDSA signature recovery should not be empty for wallet %s", walletID)

					// Compose the signature using the proper function
					composedSig, err := ComposeSignature(result.SignatureRecovery, result.R, result.S)
					if err != nil {
						t.Errorf("Failed to compose ECDSA signature for wallet %s: %v", walletID, err)
					} else {
						t.Logf("Successfully composed ECDSA signature for wallet %s: %d bytes", walletID, len(composedSig))
						assert.Equal(t, 65, len(composedSig), "Composed ECDSA signature should be 65 bytes for wallet %s", walletID)

						// Log the signature components for debugging
						t.Logf("ECDSA signature components - R: %d bytes, S: %d bytes, V: %d bytes",
							len(result.R), len(result.S), len(result.SignatureRecovery))
					}
				}
				return
			}
		}
	}
}

func testEdDSASigning(t *testing.T, suite *E2ETestSuite, walletID, message string) {
	t.Logf("Testing EdDSA signing for wallet %s with message: %s", walletID, message)

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received EdDSA signing result for wallet %s: %s", result.WalletID, result.ResultType)
		signingResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("EdDSA signing failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("EdDSA signing succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup EdDSA signing result listener")

	// Wait for listener setup
	time.Sleep(1 * time.Second)

	// Create a signing transaction message
	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  []byte(message),
		KeyType:             types.KeyTypeEd25519,
		NetworkInternalCode: "test",
	}

	// Trigger EdDSA signing
	err = suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger EdDSA signing for wallet %s", walletID)

	// Wait for signing result
	timeout := time.NewTimer(signingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for EdDSA signing result for wallet %s", walletID)
		case <-ticker.C:
			if result, exists := signingResults[walletID]; exists {
				logger.Info("Received EdDSA signing result for wallet", "result", result)
				if result.ResultType == event.ResultTypeError {
					t.Errorf("EdDSA signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("EdDSA signing succeeded for wallet %s", walletID)
					assert.NotEmpty(t, result.Signature, "EdDSA signature should not be empty for wallet %s", walletID)

					// EdDSA signatures are typically 64 bytes (32 bytes R + 32 bytes S)
					t.Logf("EdDSA signature length: %d bytes", len(result.Signature))
					if len(result.Signature) > 0 {
						assert.Equal(t, 64, len(result.Signature), "EdDSA signature should be 64 bytes for wallet %s", walletID)
					}
				}
				return
			}
		}
	}
}

func testECDSASigningWithSharedListener(t *testing.T, suite *E2ETestSuite, walletID, message string, signingResults map[string]*event.SigningResultEvent) {
	t.Logf("Testing ECDSA signing for wallet %s with message: %s", walletID, message)

	// Wait for listener setup
	time.Sleep(1 * time.Second)

	// Create a signing transaction message
	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  []byte(message),
		KeyType:             types.KeyTypeSecp256k1,
		NetworkInternalCode: "test",
	}

	// Trigger ECDSA signing
	err := suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger ECDSA signing for wallet %s", walletID)

	// Wait for signing result
	timeout := time.NewTimer(signingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for ECDSA signing result for wallet %s", walletID)
		case <-ticker.C:
			if result, exists := signingResults[txID]; exists {
				logger.Info("Received ECDSA signing result for wallet", "result", result)
				if result.ResultType == event.ResultTypeError {
					t.Errorf("ECDSA signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("ECDSA signing succeeded for wallet %s", walletID)
					assert.NotEmpty(t, result.R, "ECDSA R value should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.S, "ECDSA S value should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.SignatureRecovery, "ECDSA signature recovery should not be empty for wallet %s", walletID)

					// Compose the signature using the proper function
					composedSig, err := ComposeSignature(result.SignatureRecovery, result.R, result.S)
					if err != nil {
						t.Errorf("Failed to compose ECDSA signature for wallet %s: %v", walletID, err)
					} else {
						t.Logf("Successfully composed ECDSA signature for wallet %s: %d bytes", walletID, len(composedSig))
						assert.Equal(t, 65, len(composedSig), "Composed ECDSA signature should be 65 bytes for wallet %s", walletID)

						// Log the signature components for debugging
						t.Logf("ECDSA signature components - R: %d bytes, S: %d bytes, V: %d bytes",
							len(result.R), len(result.S), len(result.SignatureRecovery))
					}
				}
				return
			}
		}
	}
}

func testEdDSASigningWithSharedListener(t *testing.T, suite *E2ETestSuite, walletID, message string, signingResults map[string]*event.SigningResultEvent) {
	t.Logf("Testing EdDSA signing for wallet %s with message: %s", walletID, message)

	// Wait for listener setup
	time.Sleep(1 * time.Second)

	// Create a signing transaction message
	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  []byte(message),
		KeyType:             types.KeyTypeEd25519,
		NetworkInternalCode: "test",
	}

	// Trigger EdDSA signing
	err := suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger EdDSA signing for wallet %s", walletID)

	// Wait for signing result
	timeout := time.NewTimer(signingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for EdDSA signing result for wallet %s", walletID)
		case <-ticker.C:
			if result, exists := signingResults[txID]; exists {
				logger.Info("Received EdDSA signing result for wallet", "result", result)
				if result.ResultType == event.ResultTypeError {
					t.Errorf("EdDSA signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("EdDSA signing succeeded for wallet %s", walletID)
					assert.NotEmpty(t, result.Signature, "EdDSA signature should not be empty for wallet %s", walletID)

					// EdDSA signatures are typically 64 bytes (32 bytes R + 32 bytes S)
					t.Logf("EdDSA signature length: %d bytes", len(result.Signature))
					if len(result.Signature) > 0 {
						assert.Equal(t, 64, len(result.Signature), "EdDSA signature should be 64 bytes for wallet %s", walletID)
					}
				}
				return
			}
		}
	}
}
