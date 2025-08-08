package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	resharingTimeout = 10 * time.Minute
)

func TestResharing(t *testing.T) {
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

	// Setup phase
	t.Run("Setup", func(t *testing.T) {
		suite.RunMakeClean()
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.SetupMPCClient(t)
		suite.LoadConfig()
	})

	// Key generation phase
	t.Run("KeyGeneration", func(t *testing.T) {
		testKeyGenerationForResharing(t, suite)
	})

	// Resharing tests
	t.Run("ResharingAllNodes", func(t *testing.T) {
		testResharingAllNodes(t, suite)
	})

	// Signing tests after resharing
	t.Run("SigningAfterResharing", func(t *testing.T) {
		testSigningAfterResharing(t, suite)
	})
}

func testKeyGenerationForResharing(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing key generation for resharing tests...")

	// Ensure MPC client is initialized
	if suite.mpcClient == nil {
		t.Fatal("MPC client is not initialized. Make sure Setup subtest runs first.")
	}

	// Wait for all nodes to be ready before proceeding
	suite.WaitForNodesReady(t)

	// Generate 1 wallet IDs for testing (one for each key type)
	walletIDs := make([]string, 1)
	for i := 0; i < 1; i++ {
		walletIDs[i] = uuid.New().String()
		suite.walletIDs = append(suite.walletIDs, walletIDs[i])
	}

	t.Logf("Generated wallet IDs for resharing: %v", walletIDs)

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

	t.Log("Key generation for resharing tests completed")
}

func testResharingAllNodes(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing resharing with all nodes online...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for resharing. Make sure key generation ran first.")
	}

	// Get node IDs for resharing
	nodeIDs, err := suite.GetNodeIDs()
	require.NoError(t, err, "Failed to get node IDs")
	require.GreaterOrEqual(t, len(nodeIDs), 2, "Need at least 2 nodes for resharing")

	t.Logf("Available node IDs for resharing: %v", nodeIDs)

	// Setup a shared resharing result listener for all resharing tests
	err = suite.mpcClient.OnResharingResult(func(result event.ResharingResultEvent) {
		t.Logf("Received resharing result for wallet %s: %s", result.WalletID, result.ResultType)
		suite.resharingResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Resharing failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Resharing succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup resharing result listener")

	// Wait for listener setup
	time.Sleep(10 * time.Second)

	// Test resharing for both key types
	for i, walletID := range suite.walletIDs {
		t.Logf("Testing resharing for wallet %s", walletID)

		// Test ECDSA resharing (first wallet)
		if i == 0 {
			t.Run(fmt.Sprintf("ECDSA_Resharing_%s", walletID), func(t *testing.T) {
				testECDSAResharing(t, suite, walletID, nodeIDs)
			})
		}

		// Test EdDSA resharing (second wallet)
		if i == 1 {
			t.Run(fmt.Sprintf("EdDSA_Resharing_%s", walletID), func(t *testing.T) {
				testEdDSAResharing(t, suite, walletID, nodeIDs)
			})
		}
	}

	t.Log("Resharing with all nodes completed")
}

func testECDSAResharing(t *testing.T, suite *E2ETestSuite, walletID string, nodeIDs []string) {
	t.Logf("Testing ECDSA resharing for wallet %s", walletID)

	// Create resharing message for ECDSA
	sessionID := uuid.New().String()
	resharingMsg := &types.ResharingMessage{
		SessionID:    sessionID,
		WalletID:     walletID,
		NodeIDs:      nodeIDs[:2], // Use first 2 nodes for resharing
		NewThreshold: 1,           // New threshold of 2
		KeyType:      types.KeyTypeSecp256k1,
	}

	t.Logf("Sending ECDSA resharing message for wallet %s with session ID %s", walletID, sessionID)
	t.Logf("New committee: %v, New threshold: %d", resharingMsg.NodeIDs, resharingMsg.NewThreshold)

	// Send resharing message
	err := suite.mpcClient.Resharing(resharingMsg)
	require.NoError(t, err, "Failed to send ECDSA resharing message")

	// Wait for resharing result
	t.Log("Waiting for ECDSA resharing result...")

	timeout := time.NewTimer(resharingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for ECDSA resharing result for wallet %s", walletID)
		case <-ticker.C:
			t.Logf("Still waiting for ECDSA resharing result for wallet %s...", walletID)

			// Check if we got a result
			if _, exists := suite.resharingResults[walletID]; exists {
				goto checkECDSAResult
			}
		}
	}

checkECDSAResult:
	// Verify the resharing result
	result, exists := suite.resharingResults[walletID]
	require.True(t, exists, "No ECDSA resharing result received for wallet %s", walletID)

	if result.ResultType == event.ResultTypeError {
		t.Fatalf("ECDSA resharing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
	}

	t.Logf("ECDSA resharing succeeded for wallet %s", walletID)
	t.Logf("New public key: %x", result.PubKey)
	t.Logf("New threshold: %d", result.NewThreshold)
	t.Logf("Key type: %s", result.KeyType)

	// Verify the resharing result
	assert.Equal(t, event.ResultTypeSuccess, result.ResultType, "ECDSA resharing should succeed")
	assert.Equal(t, walletID, result.WalletID, "Wallet ID should match")
	assert.Equal(t, resharingMsg.NewThreshold, result.NewThreshold, "New threshold should match")
	assert.Equal(t, types.KeyTypeSecp256k1, result.KeyType, "Key type should be secp256k1")
	assert.NotEmpty(t, result.PubKey, "Public key should not be empty")

	t.Log("ECDSA resharing verification completed successfully")
}

func testEdDSAResharing(t *testing.T, suite *E2ETestSuite, walletID string, nodeIDs []string) {
	t.Logf("Testing EdDSA resharing for wallet %s", walletID)

	// Create resharing message for EdDSA
	sessionID := uuid.New().String()
	resharingMsg := &types.ResharingMessage{
		SessionID:    sessionID,
		WalletID:     walletID,
		NodeIDs:      nodeIDs[:2], // Use first 2 nodes for resharing
		NewThreshold: 1,           // New threshold of 2
		KeyType:      types.KeyTypeEd25519,
	}

	t.Logf("Sending EdDSA resharing message for wallet %s with session ID %s", walletID, sessionID)
	t.Logf("New committee: %v, New threshold: %d", resharingMsg.NodeIDs, resharingMsg.NewThreshold)

	// Send resharing message
	err := suite.mpcClient.Resharing(resharingMsg)
	require.NoError(t, err, "Failed to send EdDSA resharing message")

	// Wait for resharing result
	t.Log("Waiting for EdDSA resharing result...")

	timeout := time.NewTimer(resharingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for EdDSA resharing result for wallet %s", walletID)
		case <-ticker.C:
			t.Logf("Still waiting for EdDSA resharing result for wallet %s...", walletID)

			// Check if we got a result
			if _, exists := suite.resharingResults[walletID]; exists {
				goto checkEdDSAResult
			}
		}
	}

checkEdDSAResult:
	// Verify the resharing result
	result, exists := suite.resharingResults[walletID]
	require.True(t, exists, "No EdDSA resharing result received for wallet %s", walletID)

	if result.ResultType == event.ResultTypeError {
		t.Fatalf("EdDSA resharing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
	}

	t.Logf("EdDSA resharing succeeded for wallet %s", walletID)
	t.Logf("New public key: %x", result.PubKey)
	t.Logf("New threshold: %d", result.NewThreshold)
	t.Logf("Key type: %s", result.KeyType)

	// Verify the resharing result
	assert.Equal(t, event.ResultTypeSuccess, result.ResultType, "EdDSA resharing should succeed")
	assert.Equal(t, walletID, result.WalletID, "Wallet ID should match")
	assert.Equal(t, resharingMsg.NewThreshold, result.NewThreshold, "New threshold should match")
	assert.Equal(t, types.KeyTypeEd25519, result.KeyType, "Key type should be ed25519")
	assert.NotEmpty(t, result.PubKey, "Public key should not be empty")

	t.Log("EdDSA resharing verification completed successfully")
}

func testSigningAfterResharing(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing signing after resharing to verify reshared keys work correctly...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing after resharing. Make sure resharing ran first.")
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
	time.Sleep(10 * time.Second)

	// Test messages to sign
	testMessages := []string{
		"Reshared key test message 1",
		"Reshared key test message 2",
	}

	for _, walletID := range suite.walletIDs {
		t.Logf("Testing signing with reshared keys for wallet %s", walletID)

		for i, message := range testMessages {
			t.Logf("Signing message %d: %s", i+1, message)

			// Test ECDSA signing with reshared keys
			t.Run(fmt.Sprintf("ECDSA_Reshared_%s_%d", walletID, i), func(t *testing.T) {
				testECDSASigningAfterResharing(t, suite, walletID, message, signingResults)
			})
		}
	}

	t.Log("Signing after resharing completed")
}

func testECDSASigningAfterResharing(t *testing.T, suite *E2ETestSuite, walletID, message string, signingResults map[string]*event.SigningResultEvent) {
	t.Logf("Testing ECDSA signing with reshared keys for wallet %s with message: %s", walletID, message)

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
				t.Logf("Received ECDSA signing result for wallet %s", walletID)
				if result.ResultType == event.ResultTypeError {
					t.Errorf("ECDSA signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("ECDSA signing with reshared keys succeeded for wallet %s", walletID)
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
