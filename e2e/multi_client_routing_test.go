package e2e

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const listenerSetupDelay = 5 * time.Second

type multiClientObserver struct {
	name string

	mu sync.Mutex

	expectedWallets  map[string]struct{}
	keygenResults    map[string]event.KeygenResultEvent
	unexpectedWallet map[string]event.KeygenResultEvent

	expectedTxs  map[string]struct{}
	signResults  map[string]event.SigningResultEvent
	unexpectedTx map[string]event.SigningResultEvent
}

func TestMultiClientResultRouting(t *testing.T) {
	suite := NewE2ETestSuite(".")

	t.Log("Performing pre-test cleanup...")
	suite.CleanupTestEnvironment(t)

	defer func() {
		t.Log("Performing post-test cleanup...")
		suite.Cleanup(t)
	}()

	t.Run("Setup", func(t *testing.T) {
		t.Log("Running make clean to ensure clean build...")
		err := suite.RunMakeClean()
		require.NoError(t, err, "Failed to run make clean")

		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)

		err = suite.LoadConfig()
		require.NoError(t, err, "Failed to load config after setup")

		suite.RegisterPeers(t)
		suite.SeedPreParams(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
	})

	t.Run("ScopedKeygenAndSigning", func(t *testing.T) {
		testScopedKeygenAndSigningRouting(t, suite)
	})
}

func testScopedKeygenAndSigningRouting(t *testing.T, suite *E2ETestSuite) {
	clientA, connA := newScopedMPCClient(t, suite, "svc-a")
	defer connA.Close()

	clientB, connB := newScopedMPCClient(t, suite, "svc-b")
	defer connB.Close()

	observerA := newMultiClientObserver("A")
	observerB := newMultiClientObserver("B")

	walletA := "route-a-" + uuid.NewString()
	walletB := "route-b-" + uuid.NewString()
	observerA.expectWallet(walletA)
	observerB.expectWallet(walletB)

	require.NoError(t, clientA.OnWalletCreationResult(observerA.recordKeygen), "Failed to subscribe client A keygen results")
	require.NoError(t, clientB.OnWalletCreationResult(observerB.recordKeygen), "Failed to subscribe client B keygen results")
	require.NoError(t, clientA.OnSignResult(observerA.recordSigning), "Failed to subscribe client A signing results")
	require.NoError(t, clientB.OnSignResult(observerB.recordSigning), "Failed to subscribe client B signing results")

	time.Sleep(listenerSetupDelay)

	var createWG sync.WaitGroup
	createErrCh := make(chan error, 2)
	createWG.Add(2)
	go func() {
		defer createWG.Done()
		createErrCh <- clientA.CreateWallet(walletA)
	}()
	go func() {
		defer createWG.Done()
		createErrCh <- clientB.CreateWallet(walletB)
	}()
	createWG.Wait()
	close(createErrCh)
	for err := range createErrCh {
		require.NoError(t, err, "Scoped client failed to create wallet")
	}

	waitForKeygenRouting(t, observerA, observerB)

	observerA.assertNoUnexpectedKeygen(t)
	observerB.assertNoUnexpectedKeygen(t)
	observerA.assertKeygenSuccess(t, walletA)
	observerB.assertKeygenSuccess(t, walletB)

	txA := uuid.NewString()
	txB := uuid.NewString()
	observerA.expectTx(txA)
	observerB.expectTx(txB)

	var signWG sync.WaitGroup
	signErrCh := make(chan error, 2)
	signWG.Add(2)
	go func() {
		defer signWG.Done()
		signErrCh <- clientA.SignTransaction(&types.SignTxMessage{
			WalletID:            walletA,
			TxID:                txA,
			Tx:                  []byte("route-a-signing-payload"),
			KeyType:             types.KeyTypeEd25519,
			NetworkInternalCode: "test",
		})
	}()
	go func() {
		defer signWG.Done()
		signErrCh <- clientB.SignTransaction(&types.SignTxMessage{
			WalletID:            walletB,
			TxID:                txB,
			Tx:                  []byte("route-b-signing-payload"),
			KeyType:             types.KeyTypeEd25519,
			NetworkInternalCode: "test",
		})
	}()
	signWG.Wait()
	close(signErrCh)
	for err := range signErrCh {
		require.NoError(t, err, "Scoped client failed to sign transaction")
	}

	waitForSigningRouting(t, observerA, observerB)

	observerA.assertNoUnexpectedSigning(t)
	observerB.assertNoUnexpectedSigning(t)
	observerA.assertSigningSuccess(t, txA)
	observerB.assertSigningSuccess(t, txB)
}

func newScopedMPCClient(t *testing.T, suite *E2ETestSuite, clientID string) (client.MPCClient, *nats.Conn) {
	t.Helper()

	keyPath := filepath.Join(suite.testDir, "test_event_initiator.key")
	signer, err := client.NewLocalSigner(types.EventInitiatorKeyTypeEd25519, client.LocalSignerOptions{
		KeyPath: keyPath,
	})
	require.NoError(t, err, "Failed to create signer for client %s", clientID)

	natsConn, err := nats.Connect(suite.natsConn.ConnectedUrl())
	require.NoError(t, err, "Failed to connect scoped client %s to NATS", clientID)

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		Signer:   signer,
		ClientID: clientID,
	})

	return mpcClient, natsConn
}

func newMultiClientObserver(name string) *multiClientObserver {
	return &multiClientObserver{
		name:             name,
		expectedWallets:  make(map[string]struct{}),
		keygenResults:    make(map[string]event.KeygenResultEvent),
		unexpectedWallet: make(map[string]event.KeygenResultEvent),
		expectedTxs:      make(map[string]struct{}),
		signResults:      make(map[string]event.SigningResultEvent),
		unexpectedTx:     make(map[string]event.SigningResultEvent),
	}
}

func (o *multiClientObserver) expectWallet(walletID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.expectedWallets[walletID] = struct{}{}
}

func (o *multiClientObserver) expectTx(txID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.expectedTxs[txID] = struct{}{}
}

func (o *multiClientObserver) recordKeygen(result event.KeygenResultEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, ok := o.expectedWallets[result.WalletID]; ok {
		if _, exists := o.keygenResults[result.WalletID]; !exists {
			o.keygenResults[result.WalletID] = result
		}
		return
	}

	o.unexpectedWallet[result.WalletID] = result
}

func (o *multiClientObserver) recordSigning(result event.SigningResultEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, ok := o.expectedTxs[result.TxID]; ok {
		if _, exists := o.signResults[result.TxID]; !exists {
			o.signResults[result.TxID] = result
		}
		return
	}

	o.unexpectedTx[result.TxID] = result
}

func (o *multiClientObserver) keygenComplete() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.keygenResults) == len(o.expectedWallets)
}

func (o *multiClientObserver) signingComplete() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.signResults) == len(o.expectedTxs)
}

func (o *multiClientObserver) hasUnexpectedKeygen() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.unexpectedWallet) > 0
}

func (o *multiClientObserver) hasUnexpectedSigning() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.unexpectedTx) > 0
}

func (o *multiClientObserver) assertNoUnexpectedKeygen(t *testing.T) {
	t.Helper()

	o.mu.Lock()
	defer o.mu.Unlock()
	assert.Empty(t, sortedKeygenKeys(o.unexpectedWallet), "client %s received unexpected keygen results", o.name)
}

func (o *multiClientObserver) assertNoUnexpectedSigning(t *testing.T) {
	t.Helper()

	o.mu.Lock()
	defer o.mu.Unlock()
	assert.Empty(t, sortedSigningKeys(o.unexpectedTx), "client %s received unexpected signing results", o.name)
}

func (o *multiClientObserver) assertKeygenSuccess(t *testing.T, walletID string) {
	t.Helper()

	o.mu.Lock()
	defer o.mu.Unlock()

	result, ok := o.keygenResults[walletID]
	require.True(t, ok, "client %s missing keygen result for wallet %s", o.name, walletID)
	assert.Equal(t, event.ResultTypeSuccess, result.ResultType, "client %s keygen result for wallet %s should succeed", o.name, walletID)
	assert.NotEmpty(t, result.ECDSAPubKey, "client %s ECDSA pubkey should not be empty", o.name)
	assert.NotEmpty(t, result.EDDSAPubKey, "client %s EdDSA pubkey should not be empty", o.name)
}

func (o *multiClientObserver) assertSigningSuccess(t *testing.T, txID string) {
	t.Helper()

	o.mu.Lock()
	defer o.mu.Unlock()

	result, ok := o.signResults[txID]
	require.True(t, ok, "client %s missing signing result for tx %s", o.name, txID)
	assert.Equal(t, event.ResultTypeSuccess, result.ResultType, "client %s signing result for tx %s should succeed", o.name, txID)
	assert.NotEmpty(t, result.Signature, "client %s signature should not be empty", o.name)
}

func (o *multiClientObserver) keygenSnapshot() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return fmt.Sprintf(
		"client %s expected wallets=%v received wallets=%v unexpected wallets=%v",
		o.name,
		sortedStringSet(o.expectedWallets),
		sortedKeygenKeys(o.keygenResults),
		sortedKeygenKeys(o.unexpectedWallet),
	)
}

func (o *multiClientObserver) signingSnapshot() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return fmt.Sprintf(
		"client %s expected txs=%v received txs=%v unexpected txs=%v",
		o.name,
		sortedStringSet(o.expectedTxs),
		sortedSigningKeys(o.signResults),
		sortedSigningKeys(o.unexpectedTx),
	)
}

func waitForKeygenRouting(t *testing.T, observers ...*multiClientObserver) {
	t.Helper()

	waitForPhase(
		t,
		keygenTimeout,
		func(o *multiClientObserver) bool { return o.keygenComplete() },
		func(o *multiClientObserver) bool { return o.hasUnexpectedKeygen() },
		func(o *multiClientObserver) string { return o.keygenSnapshot() },
		observers...,
	)
}

func waitForSigningRouting(t *testing.T, observers ...*multiClientObserver) {
	t.Helper()

	waitForPhase(
		t,
		signingTimeout,
		func(o *multiClientObserver) bool { return o.signingComplete() },
		func(o *multiClientObserver) bool { return o.hasUnexpectedSigning() },
		func(o *multiClientObserver) string { return o.signingSnapshot() },
		observers...,
	)
}

func waitForPhase(
	t *testing.T,
	timeout time.Duration,
	isComplete func(*multiClientObserver) bool,
	hasUnexpected func(*multiClientObserver) bool,
	snapshot func(*multiClientObserver) string,
	observers ...*multiClientObserver,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		allComplete := true
		for _, observer := range observers {
			if hasUnexpected(observer) {
				t.Fatalf("unexpected routed result detected: %s", snapshot(observer))
			}
			if !isComplete(observer) {
				allComplete = false
			}
		}
		if allComplete {
			return
		}
		if time.Now().After(deadline) {
			snapshots := make([]string, 0, len(observers))
			for _, observer := range observers {
				snapshots = append(snapshots, snapshot(observer))
			}
			t.Fatalf("timed out waiting for routed results: %s", strings.Join(snapshots, " | "))
		}
		<-ticker.C
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	slices.Sort(keys)
	return keys
}

func sortedKeygenKeys(values map[string]event.KeygenResultEvent) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sortedSigningKeys(values map[string]event.SigningResultEvent) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
