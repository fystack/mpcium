package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGeneration(t *testing.T) {
	suite := NewE2ETestSuite(".")

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
		t.Log("Starting setupInfrastructure...")
		suite.SetupInfrastructure(t)
		t.Log("setupInfrastructure completed")

		t.Log("Starting setupTestNodes...")
		suite.SetupTestNodes(t)
		t.Log("setupTestNodes completed")

		// Load config after setup script runs
		err := suite.LoadConfig()
		require.NoError(t, err, "Failed to load config after setup")

		t.Log("Starting registerPeers...")
		suite.RegisterPeers(t)
		t.Log("registerPeers completed")

		t.Log("Starting startNodes...")
		suite.StartNodes(t)
		t.Log("startNodes completed")

		t.Log("Waiting for node ready")
		// Wait for all nodes to be ready before proceeding
		suite.WaitForNodesReady(t)
		t.Log("Waiting for node completed")

		t.Log("Starting setupMPCClient...")
		suite.SetupMPCClient(t)
		t.Log("setupMPCClient completed")

	})

	// Test key generation
	t.Run("KeyGeneration", func(t *testing.T) {
		testKeyGeneration(t, suite)
	})

	// Verify consistency
	t.Run("VerifyConsistency", func(t *testing.T) {
		verifyKeyConsistency(t, suite)
	})
}

func testKeyGeneration(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing key generation...")

	// Ensure MPC client is initialized
	if suite.mpcClient == nil {
		t.Fatal("MPC client is not initialized. Make sure Setup subtest runs first.")
	}
	// Generate 1 wallet ID for testing
	walletIDs := make([]string, 0, 10)
	for i := 0; i < 1; i++ {
		walletIDs = append(walletIDs, uuid.New().String())
		suite.walletIDs = append(suite.walletIDs, walletIDs[i])
	}

	logger.Info(fmt.Sprintf("Generated wallet IDs: %v", walletIDs))

	// Setup result listener
	err := suite.mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		logger.Info("On wallet creation result", "event", result)
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

			// Show recent logs from nodes to debug what's happening
			t.Log("Recent logs from MPC nodes:")
			for i := 0; i < numNodes; i++ {
				nodeName := fmt.Sprintf("test_node%d", i)
				suite.ShowRecentLogs(t, nodeName)
			}

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

	t.Log("Key generation test completed")
}

func verifyKeyConsistency(t *testing.T, suite *E2ETestSuite) {
	t.Log("Verifying key consistency across nodes...")

	// Stop all nodes first to safely access databases
	suite.StopNodes(t)

	// Check each wallet's keys in all node databases
	for _, walletID := range suite.walletIDs {
		t.Logf("Checking wallet %s", walletID)

		// Check both ECDSA and EdDSA keys
		suite.CheckKeyInAllNodes(t, walletID, "ecdsa", "ECDSA")
		suite.CheckKeyInAllNodes(t, walletID, "eddsa", "EdDSA")
	}

	t.Log("Key consistency verification completed")
}
