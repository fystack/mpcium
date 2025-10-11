package e2e

import (
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaurusCMPKeyGeneration(t *testing.T) {
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
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		suite.LoadConfig()
		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
		suite.SetupMPCClient(t)
	})

	// Test Taurus CMP key generation
	t.Run("TaurusCMPKeyGeneration", func(t *testing.T) {
		testTaurusCMPKeyGeneration(t, suite)
	})

	// Verify key consistency across nodes
	t.Run("VerifyTaurusCMPConsistency", func(t *testing.T) {
		verifyTaurusCMPKeyConsistency(t, suite)
	})
}

func TestTaurusCMPSigning(t *testing.T) {
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
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		suite.LoadConfig()
		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
		suite.SetupMPCClient(t)
	})

	// Generate keys first
	t.Run("KeyGenerationForSigning", func(t *testing.T) {
		testTaurusCMPKeyGeneration(t, suite)
	})

	// Test Taurus CMP signing
	t.Run("TaurusCMPSigning", func(t *testing.T) {
		testTaurusCMPSigning(t, suite)
	})
}

func TestTaurusCMPResharing(t *testing.T) {
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
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		suite.LoadConfig()
		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
		suite.SetupMPCClient(t)
	})

	// Generate keys first
	t.Run("KeyGenerationForResharing", func(t *testing.T) {
		testTaurusCMPKeyGeneration(t, suite)
	})

	// Test Taurus CMP resharing
	t.Run("TaurusCMPResharing", func(t *testing.T) {
		testTaurusCMPResharing(t, suite)
	})

	// Test signing after resharing
	t.Run("SigningAfterResharing", func(t *testing.T) {
		testTaurusCMPSigning(t, suite)
	})
}

func TestMixedProtocolKeyGeneration(t *testing.T) {
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
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		suite.LoadConfig()
		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
		suite.SetupMPCClient(t)
	})

	// Test that all three protocols work in parallel
	t.Run("MixedProtocolKeyGeneration", func(t *testing.T) {
		testMixedProtocolKeyGeneration(t, suite)
	})

	// Verify all keys are consistent
	t.Run("VerifyMixedProtocolConsistency", func(t *testing.T) {
		verifyMixedProtocolConsistency(t, suite)
	})
}

func testTaurusCMPKeyGeneration(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing Taurus CMP key generation...")

	// Ensure MPC client is initialized
	if suite.mpcClient == nil {
		t.Fatal("MPC client is not initialized. Make sure Setup subtest runs first.")
	}

	// Generate 1 wallet ID for Taurus CMP testing
	walletID := uuid.New().String()
	suite.walletIDs = append(suite.walletIDs, walletID)

	t.Logf("Generated wallet ID for Taurus CMP: %s", walletID)

	// Setup result listener
	err := suite.mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		t.Logf("Received Taurus CMP keygen result for wallet %s: %s", result.WalletID, result.ResultType)
		suite.keygenResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Taurus CMP keygen failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Taurus CMP keygen succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup Taurus CMP keygen result listener")

	// Add longer delay to ensure listener is fully established
	t.Log("Waiting for result listener to be fully established...")
	time.Sleep(15 * time.Second)

	// Trigger key generation
	t.Logf("Triggering Taurus CMP key generation for wallet %s", walletID)
	err = suite.mpcClient.CreateWallet(walletID)
	require.NoError(t, err, "Failed to trigger Taurus CMP key generation for wallet %s", walletID)

	// Wait for key generation to complete
	t.Log("Waiting for Taurus CMP key generation to complete...")

	timeout := time.NewTimer(keygenTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for Taurus CMP keygen result for wallet %s", walletID)
		case <-ticker.C:
			t.Logf("Still waiting for Taurus CMP keygen result for wallet %s...", walletID)

			if result, exists := suite.keygenResults[walletID]; exists {
				if result.ResultType == event.ResultTypeError {
					t.Errorf("Taurus CMP keygen failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				} else {
					t.Logf("Taurus CMP keygen succeeded for wallet %s", result.WalletID)

					// Validate that we have all three key types
					assert.NotEmpty(t, result.ECDSAPubKey, "ECDSA public key should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.EDDSAPubKey, "EdDSA public key should not be empty for wallet %s", walletID)
					assert.NotEmpty(t, result.TaurusCMPPubKey, "Taurus CMP public key should not be empty for wallet %s", walletID)

					// Log key sizes for debugging
					t.Logf("Key sizes - ECDSA: %d bytes, EdDSA: %d bytes, Taurus CMP: %d bytes",
						len(result.ECDSAPubKey), len(result.EDDSAPubKey), len(result.TaurusCMPPubKey))
				}
				return
			}
		}
	}
}

func testTaurusCMPSigning(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing Taurus CMP signing...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for Taurus CMP signing. Make sure key generation ran first.")
	}

	walletID := suite.walletIDs[0]
	t.Logf("Testing Taurus CMP signing for wallet %s", walletID)

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received Taurus CMP signing result for wallet %s (tx: %s): %s", result.WalletID, result.TxID, result.ResultType)
		signingResults[result.TxID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Taurus CMP signing failed for wallet %s (tx: %s): %s (%s)", result.WalletID, result.TxID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Taurus CMP signing succeeded for wallet %s (tx: %s)", result.WalletID, result.TxID)
		}
	})
	require.NoError(t, err, "Failed to setup Taurus CMP signing result listener")

	// Wait for listener setup
	time.Sleep(2 * time.Second)

	// Test messages to sign
	testMessages := []string{
		"Taurus CMP Test Message 1",
		"Taurus CMP Test Message 2",
		"Taurus CMP Test Message 3",
	}

	for i, message := range testMessages {
		t.Logf("Testing Taurus CMP signing message %d: %s", i+1, message)

		// Create signing transaction message for Taurus CMP
		txID := uuid.New().String()
		signTxMsg := &types.SignTxMessage{
			WalletID:            walletID,
			TxID:                txID,
			Tx:                  []byte(message),
			KeyType:             types.KeyTypeTaurusCmp,
			NetworkInternalCode: "test",
		}

		// Trigger Taurus CMP signing
		err := suite.mpcClient.SignTransaction(signTxMsg)
		require.NoError(t, err, "Failed to trigger Taurus CMP signing for wallet %s", walletID)

		// Wait for signing result
		timeout := time.NewTimer(signingTimeout)
		defer timeout.Stop()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-timeout.C:
				t.Fatalf("Timeout waiting for Taurus CMP signing result for wallet %s, tx %s", walletID, txID)
			case <-ticker.C:
				if result, exists := signingResults[txID]; exists {
					if result.ResultType == event.ResultTypeError {
						t.Errorf("Taurus CMP signing failed for wallet %s (tx: %s): %s (%s)", walletID, txID, result.ErrorReason, result.ErrorCode)
					} else {
						t.Logf("Taurus CMP signing succeeded for wallet %s (tx: %s)", walletID, txID)
						assert.NotEmpty(t, result.Signature, "Taurus CMP signature should not be empty for wallet %s", walletID)

						// Taurus CMP signatures should be 65 bytes (like ECDSA Ethereum format)
						t.Logf("Taurus CMP signature length: %d bytes", len(result.Signature))
						if len(result.Signature) > 0 {
							assert.Equal(t, 65, len(result.Signature), "Taurus CMP signature should be 65 bytes for wallet %s", walletID)
						}
					}
					goto nextMessage
				}
			}
		}
	nextMessage:
	}

	t.Log("Taurus CMP signing test completed")
}

func testTaurusCMPResharing(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing Taurus CMP resharing...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for Taurus CMP resharing. Make sure key generation ran first.")
	}

	walletID := suite.walletIDs[0]
	t.Logf("Testing Taurus CMP resharing for wallet %s", walletID)

	// Get node IDs for resharing
	nodeIDs, err := suite.GetNodeIDs()
	require.NoError(t, err, "Failed to get node IDs")
	require.GreaterOrEqual(t, len(nodeIDs), 2, "Need at least 2 nodes for resharing")

	// Setup resharing result listener
	err = suite.mpcClient.OnResharingResult(func(result event.ResharingResultEvent) {
		t.Logf("Received Taurus CMP resharing result for wallet %s: %s", result.WalletID, result.ResultType)
		suite.resharingResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Taurus CMP resharing failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Taurus CMP resharing succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup Taurus CMP resharing result listener")

	// Wait for listener setup
	time.Sleep(10 * time.Second)

	// Create resharing message for Taurus CMP
	sessionID := uuid.New().String()
	resharingMsg := &types.ResharingMessage{
		SessionID:    sessionID,
		WalletID:     walletID,
		NodeIDs:      nodeIDs[:2], // Use first 2 nodes for resharing
		NewThreshold: 1,           // New threshold of 1
		KeyType:      types.KeyTypeTaurusCmp,
	}

	t.Logf("Sending Taurus CMP resharing message for wallet %s with session ID %s", walletID, sessionID)
	t.Logf("New committee: %v, New threshold: %d", resharingMsg.NodeIDs, resharingMsg.NewThreshold)

	// Send resharing message
	err = suite.mpcClient.Resharing(resharingMsg)
	require.NoError(t, err, "Failed to send Taurus CMP resharing message")

	// Wait for resharing result
	t.Log("Waiting for Taurus CMP resharing result...")

	timeout := time.NewTimer(resharingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for Taurus CMP resharing result for wallet %s", walletID)
		case <-ticker.C:
			t.Logf("Still waiting for Taurus CMP resharing result for wallet %s...", walletID)

			// Check if we got a result
			if result, exists := suite.resharingResults[walletID]; exists {
				if result.ResultType == event.ResultTypeError {
					t.Fatalf("Taurus CMP resharing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
				}

				t.Logf("Taurus CMP resharing succeeded for wallet %s", walletID)
				t.Logf("New public key: %x", result.PubKey)
				t.Logf("New threshold: %d", result.NewThreshold)

				// Validate resharing result
				assert.NotEmpty(t, result.PubKey, "Taurus CMP public key should not be empty after resharing")
				assert.Equal(t, resharingMsg.NewThreshold, result.NewThreshold, "New threshold should match")
				return
			}
		}
	}
}

func testMixedProtocolKeyGeneration(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing mixed protocol key generation (ECDSA + EdDSA + Taurus CMP)...")

	// This test validates that all three protocols work together in the same wallet
	// The current implementation generates all three key types simultaneously
	testTaurusCMPKeyGeneration(t, suite)

	// Verify that we indeed got all three key types
	if len(suite.keygenResults) > 0 {
		for walletID, result := range suite.keygenResults {
			t.Logf("Validating mixed protocol keys for wallet %s", walletID)

			assert.NotEmpty(t, result.ECDSAPubKey, "ECDSA key missing in mixed protocol")
			assert.NotEmpty(t, result.EDDSAPubKey, "EdDSA key missing in mixed protocol")
			assert.NotEmpty(t, result.TaurusCMPPubKey, "Taurus CMP key missing in mixed protocol")

			t.Logf("Mixed protocol validation passed for wallet %s", walletID)
		}
	}
}

func verifyTaurusCMPKeyConsistency(t *testing.T, suite *E2ETestSuite) {
	t.Log("Verifying Taurus CMP key consistency across nodes...")

	// Stop all nodes first to safely access databases
	suite.StopNodes(t)

	// Check each wallet's Taurus CMP keys in all node databases
	for _, walletID := range suite.walletIDs {
		t.Logf("Checking Taurus CMP keys for wallet %s", walletID)

		// Check Taurus CMP keys
		suite.CheckKeyInAllNodes(t, walletID, "taurus_cmp", "Taurus CMP")
	}

	t.Log("Taurus CMP key consistency verification completed")
}

func verifyMixedProtocolConsistency(t *testing.T, suite *E2ETestSuite) {
	t.Log("Verifying mixed protocol key consistency across nodes...")

	// Stop all nodes first to safely access databases
	suite.StopNodes(t)

	// Check each wallet's keys in all node databases
	for _, walletID := range suite.walletIDs {
		t.Logf("Checking mixed protocol keys for wallet %s", walletID)

		// Check all three key types
		suite.CheckKeyInAllNodes(t, walletID, "ecdsa", "ECDSA")
		suite.CheckKeyInAllNodes(t, walletID, "eddsa", "EdDSA")
		suite.CheckKeyInAllNodes(t, walletID, "taurus_cmp", "Taurus CMP")
	}

	t.Log("Mixed protocol key consistency verification completed")
}
