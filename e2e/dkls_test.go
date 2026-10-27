package e2e

import (
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Needs `mpcium` in PATH built with -tags dkls; run with E2E_DKLS=1.
func TestDklsSigning(t *testing.T) {
	if os.Getenv("E2E_DKLS") == "" {
		t.Skip("set E2E_DKLS=1 and put a -tags dkls mpcium build in PATH")
	}

	suite := NewE2ETestSuite(".")
	logger.Init("dev", true)
	suite.CleanupTestEnvironment(t)
	defer suite.Cleanup(t)

	keygens := make(chan event.KeygenResultEvent, 8)
	signs := make(chan event.SigningResultEvent, 8)
	refreshes := make(chan event.ResharingResultEvent, 8)
	walletID := uuid.NewString()
	var masterPub *btcec.PublicKey
	hash := sha256.Sum256([]byte("dkls e2e"))

	t.Run("Setup", func(t *testing.T) {
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)
		require.NoError(t, suite.LoadConfig())
		suite.RegisterPeers(t)
		suite.SetupMPCClient(t)
		suite.SeedPreParams(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)

		require.NoError(t, suite.mpcClient.OnWalletCreationResult(func(e event.KeygenResultEvent) { keygens <- e }))
		require.NoError(t, suite.mpcClient.OnSignResult(func(e event.SigningResultEvent) { signs <- e }))
		require.NoError(t, suite.mpcClient.OnResharingResult(func(e event.ResharingResultEvent) { refreshes <- e }))
		time.Sleep(5 * time.Second)
	})

	t.Run("KeyGeneration", func(t *testing.T) {
		require.NoError(t, suite.mpcClient.CreateWalletWithProtocol(walletID, types.ProtocolDkls23, nil))
		var res event.KeygenResultEvent
		select {
		case res = <-keygens:
		case <-time.After(keygenTimeout):
			t.Fatal("timed out waiting for keygen result")
		}
		require.Equal(t, event.ResultTypeSuccess, res.ResultType, res.ErrorReason)
		require.Len(t, res.DKLSPubKey, 64)
		require.NotEmpty(t, res.DKLSChainCode)

		var err error
		masterPub, err = btcec.ParsePubKey(append([]byte{0x04}, res.DKLSPubKey...))
		require.NoError(t, err)
	})

	sign := func(t *testing.T, path []uint32) *btcec.PublicKey {
		require.NoError(t, suite.mpcClient.SignTransaction(&types.SignTxMessage{
			KeyType:             types.KeyTypeSecp256k1,
			Protocol:            types.ProtocolDkls23,
			WalletID:            walletID,
			NetworkInternalCode: "e2e",
			TxID:                uuid.NewString(),
			Tx:                  hash[:],
			DerivationPath:      path,
		}))
		var res event.SigningResultEvent
		select {
		case res = <-signs:
		case <-time.After(signingTimeout):
			t.Fatal("timed out waiting for signing result")
		}
		require.Equal(t, event.ResultTypeSuccess, res.ResultType, res.ErrorReason)

		compact := append([]byte{27 + 4 + res.SignatureRecovery[0]}, res.Signature...)
		pub, _, err := btcecdsa.RecoverCompact(compact, hash[:])
		require.NoError(t, err)
		return pub
	}

	// Signs right after keygen: nodes may still be saving their share.
	t.Run("Signing", func(t *testing.T) {
		require.True(t, sign(t, nil).IsEqual(masterPub), "signature does not recover to the DKG public key")
	})

	t.Run("ChildKeySigning", func(t *testing.T) {
		require.False(t, sign(t, []uint32{1, 5}).IsEqual(masterPub), "child signature recovered to the master key")
	})

	t.Run("Refresh", func(t *testing.T) {
		sessionID := uuid.NewString()
		require.NoError(t, suite.mpcClient.RefreshDkls(&types.RefreshMessage{WalletID: walletID, SessionID: sessionID}))
		var res event.ResharingResultEvent
		select {
		case res = <-refreshes:
		case <-time.After(keygenTimeout):
			t.Fatal("timed out waiting for refresh result")
		}
		require.Equal(t, event.ResultTypeSuccess, res.ResultType, res.ErrorReason)
		require.Equal(t, append([]byte{0x04}, res.PubKey...), masterPub.SerializeUncompressed(), "refresh changed the public key")
	})

	t.Run("SigningAfterRefresh", func(t *testing.T) {
		require.True(t, sign(t, nil).IsEqual(masterPub), "signature does not recover to the DKG public key")
	})

	// A killed node never resigns, so refresh only fails once the 60s phase timeout expires.
	refreshFails := func(t *testing.T, id string) event.ResharingResultEvent {
		require.NoError(t, suite.mpcClient.RefreshDkls(&types.RefreshMessage{WalletID: id, SessionID: uuid.NewString()}))
		select {
		case res := <-refreshes:
			require.Equal(t, event.ResultTypeError, res.ResultType)
			return res
		case <-time.After(90 * time.Second):
			t.Fatal("timed out waiting for refresh error result")
			return event.ResharingResultEvent{}
		}
	}

	t.Run("RefreshUnknownWallet", func(t *testing.T) {
		refreshFails(t, uuid.NewString())
	})

	t.Run("RefreshWithNodeOffline", func(t *testing.T) {
		suite.StopNode(t, 2)
		refreshFails(t, walletID)
	})
}
