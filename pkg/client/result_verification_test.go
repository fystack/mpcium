package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/resultauth"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type capturingQueue struct {
	messaging.MessageQueue
	handler  func(msg messaging.Message) error
	handlers []func(msg messaging.Message) error
	settled  []error
}

// DequeueMessageAsync exposes each subscription as a handler that returns the settle error, or nil while still pending.
func (q *capturingQueue) DequeueMessageAsync(_ string, handler func(msg messaging.Message, done func(err error))) error {
	q.handler = func(msg messaging.Message) error {
		var settleErr error
		handler(msg, func(err error) {
			settleErr = err
			q.settled = append(q.settled, err)
		})
		return settleErr
	}
	q.handlers = append(q.handlers, q.handler)
	return nil
}

type testNode struct {
	id         string
	privateKey ed25519.PrivateKey
}

func (n testNode) Sign(data []byte) ([]byte, error) { return ed25519.Sign(n.privateKey, data), nil }

func newTestNodes(t *testing.T, count int) ([]testNode, map[string]string) {
	t.Helper()
	nodes := make([]testNode, 0, count)
	publicKeys := make(map[string]string, count)
	for i := range count {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		node := testNode{id: string(rune('a' + i)), privateKey: privateKey}
		nodes = append(nodes, node)
		publicKeys[node.id] = hex.EncodeToString(publicKey)
	}
	return nodes, publicKeys
}

func signedMessage(t *testing.T, node testNode, subject string, payload any) messaging.Message {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	headers, err := resultauth.SignHeaders(node, node.id, subject, body)
	require.NoError(t, err)
	header := nats.Header{}
	for k, v := range headers {
		header.Set(k, v)
	}
	return messaging.Message{Subject: subject, Data: body, Header: header}
}

func newSigningResultClient(t *testing.T, mode ResultVerifyMode, publicKeys map[string]string) (*capturingQueue, *[]event.SigningResultEvent) {
	t.Helper()
	verifier, err := newResultVerifier(mode, publicKeys, 0)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{signResultQueue: queue, resultVerifier: verifier}
	var delivered []event.SigningResultEvent
	require.NoError(t, c.OnSignResult(func(e event.SigningResultEvent) { delivered = append(delivered, e) }))
	return queue, &delivered
}

func newKeygenResultClient(t *testing.T, publicKeys map[string]string, required int) (*mpcClient, *capturingQueue, *[]event.KeygenResultEvent) {
	t.Helper()
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, required)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{genKeySuccessQueue: queue, resultVerifier: verifier}
	var delivered []event.KeygenResultEvent
	require.NoError(t, c.OnWalletCreationResult(func(e event.KeygenResultEvent) { delivered = append(delivered, e) }))
	return c, queue, &delivered
}

func TestOnSignResultEnforceDeliversValidCopy(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyEnforce, publicKeys)
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], event.SigningResultSubject(""), success)))
	require.Len(t, *delivered, 1)
	require.Equal(t, "tx-1", (*delivered)[0].TxID)
	require.Equal(t, []error{nil}, queue.settled)
}

func TestOnSignResultEnforceRejectsForgedResults(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyEnforce, publicKeys)
	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	unsigned := signedMessage(t, nodes[0], subject, success)
	unsigned.Header = nats.Header{}
	require.ErrorIs(t, queue.handler(unsigned), messaging.ErrPermament)

	tampered := signedMessage(t, nodes[0], subject, success)
	tampered.Data = []byte(`{"result_type":"success","tx_id":"tx-1","signature":"Zm9yZ2Vk"}`)
	require.ErrorIs(t, queue.handler(tampered), messaging.ErrPermament)

	wrongSubject := signedMessage(t, nodes[0], event.SigningResultSubject("other-client"), success)
	wrongSubject.Subject = subject
	require.ErrorIs(t, queue.handler(wrongSubject), messaging.ErrPermament)

	_, outsiderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	outsider := testNode{id: "outsider", privateKey: outsiderKey}
	require.ErrorIs(t, queue.handler(signedMessage(t, outsider, subject, success)), messaging.ErrPermament)

	impostor := testNode{id: nodes[1].id, privateKey: outsiderKey}
	require.ErrorIs(t, queue.handler(signedMessage(t, impostor, subject, success)), messaging.ErrPermament)

	require.Empty(t, *delivered)
}

func TestOnSignResultLogModeDeliversUnsignedResults(t *testing.T) {
	_, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyLog, publicKeys)
	body, err := json.Marshal(event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1"})
	require.NoError(t, err)

	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.Len(t, *delivered, 1)
}

func TestOnSignResultOffDeliversEveryResult(t *testing.T) {
	queue, delivered := newSigningResultClient(t, "", nil)
	body, err := json.Marshal(event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1"})
	require.NoError(t, err)

	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.Len(t, *delivered, 2)
}

func TestOnResharingResultEnforceDeliversValidCopy(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, 2)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{reshareSuccessQueue: queue, resultVerifier: verifier}
	var delivered []event.ResharingResultEvent
	require.NoError(t, c.OnResharingResult(func(e event.ResharingResultEvent) { delivered = append(delivered, e) }))

	subject := event.ReshareResultSubject("", "session-1")
	success := event.ResharingResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", PubKey: []byte("pub")}
	unsigned := signedMessage(t, nodes[0], subject, success)
	unsigned.Header = nats.Header{}
	require.ErrorIs(t, queue.handler(unsigned), messaging.ErrPermament)

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.Len(t, delivered, 1, "reshare needs no quorum; the caller checks the public key is unchanged")
}

func TestOnWalletCreationResultWaitsForRequiredNodes(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	_, queue, delivered := newKeygenResultClient(t, publicKeys, 2)
	subject := event.KeygenResultSubject("", "wallet-1")
	success := event.KeygenResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", ECDSAPubKey: []byte("pub")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.Empty(t, *delivered)
	require.Empty(t, queue.settled, "a copy waiting for quorum must stay unacked so a crash redelivers it")

	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, success)))
	require.Len(t, *delivered, 1)
	require.Equal(t, []error{nil, nil}, queue.settled)

	require.NoError(t, queue.handler(signedMessage(t, nodes[2], subject, success)))
	require.Len(t, *delivered, 1, "a late copy must not deliver again")
	require.Len(t, queue.settled, 3)
}

func TestOnWalletCreationResultForgedPubKeyNeedsQuorum(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	_, queue, delivered := newKeygenResultClient(t, publicKeys, 2)
	subject := event.KeygenResultSubject("", "wallet-1")
	honest := event.KeygenResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", ECDSAPubKey: []byte("honest")}
	forged := event.KeygenResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", ECDSAPubKey: []byte("attacker")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, forged)))
	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, honest)))
	require.Empty(t, *delivered)
	require.NoError(t, queue.handler(signedMessage(t, nodes[2], subject, honest)))

	require.Len(t, *delivered, 1)
	require.Equal(t, []byte("honest"), (*delivered)[0].ECDSAPubKey)
}

func TestOnWalletCreationResultSubscriptionsShareOneAggregator(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	c, queue, first := newKeygenResultClient(t, publicKeys, 2)
	var second []event.KeygenResultEvent
	require.NoError(t, c.OnWalletCreationResult(func(e event.KeygenResultEvent) { second = append(second, e) }))
	require.Len(t, queue.handlers, 2)

	subject := event.KeygenResultSubject("", "wallet-1")
	success := event.KeygenResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", ECDSAPubKey: []byte("pub")}
	require.NoError(t, queue.handlers[0](signedMessage(t, nodes[0], subject, success)))
	require.NoError(t, queue.handlers[1](signedMessage(t, nodes[1], subject, success)))

	require.Empty(t, *first)
	require.Len(t, second, 1, "copies split across subscriptions must still reach t+1 once")
}

func TestCreateWalletRequestsPerNodeCopiesOnlyWithQuorum(t *testing.T) {
	_, publicKeys := newTestNodes(t, 3)
	for _, tt := range []struct {
		name     string
		required int
		want     string
	}{
		{"single copy", 1, ""},
		{"t+1 copies", 2, event.KeygenResultCopiesPerNode},
	} {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, tt.required)
			require.NoError(t, err)
			broker := &recordingBroker{}
			c := &mpcClient{keygenBroker: broker, signer: staticSigner{}, resultVerifier: verifier}

			require.NoError(t, c.CreateWallet("wallet-1"))
			require.Equal(t, tt.want, broker.headers[event.KeygenResultCopiesHeader])
		})
	}
}

func TestNewResultVerifierValidation(t *testing.T) {
	_, publicKeys := newTestNodes(t, 2)
	tests := []struct {
		name       string
		mode       ResultVerifyMode
		publicKeys map[string]string
		required   int
		wantErr    bool
	}{
		{"off needs nothing", ResultVerifyOff, nil, 0, false},
		{"off with keygen quorum", ResultVerifyOff, nil, 2, true},
		{"log with keygen quorum", ResultVerifyLog, publicKeys, 2, true},
		{"unknown mode", "strict", publicKeys, 1, true},
		{"enforce without keys", ResultVerifyEnforce, nil, 1, true},
		{"required above key count", ResultVerifyEnforce, publicKeys, 3, true},
		{"bad key", ResultVerifyLog, map[string]string{"a": "zz"}, 1, true},
		{"valid enforce", ResultVerifyEnforce, publicKeys, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newResultVerifier(tt.mode, tt.publicKeys, tt.required)
			require.Equal(t, tt.wantErr, err != nil, err)
		})
	}
}

type staticSigner struct{}

func (staticSigner) Sign([]byte) ([]byte, error) { return []byte("sig"), nil }

func (staticSigner) Algorithm() types.EventInitiatorKeyType {
	return types.EventInitiatorKeyTypeEd25519
}

func (staticSigner) PublicKey() (string, error) { return "", nil }
