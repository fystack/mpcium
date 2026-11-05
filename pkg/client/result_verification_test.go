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

func newSigningResultClient(t *testing.T, mode ResultVerifyMode, publicKeys map[string]string, required int) (*capturingQueue, *[]event.SigningResultEvent) {
	t.Helper()
	verifier, err := newResultVerifier(mode, publicKeys, required)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{signResultQueue: queue, resultVerifier: verifier}
	var delivered []event.SigningResultEvent
	require.NoError(t, c.OnSignResult(func(e event.SigningResultEvent) { delivered = append(delivered, e) }))
	return queue, &delivered
}

func TestOnSignResultEnforceWaitsForRequiredNodes(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyEnforce, publicKeys, 2)
	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.Empty(t, *delivered)
	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, success)))
	require.NoError(t, queue.handler(signedMessage(t, nodes[2], subject, success)))

	require.Len(t, *delivered, 1)
	require.Equal(t, "tx-1", (*delivered)[0].TxID)
}

func TestOnSignResultEnforceRejectsForgedResults(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyEnforce, publicKeys, 2)
	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	unsigned := signedMessage(t, nodes[0], subject, success)
	unsigned.Header = nats.Header{}
	require.ErrorIs(t, queue.handler(unsigned), messaging.ErrPermament)

	tampered := signedMessage(t, nodes[0], subject, success)
	tampered.Data = []byte(`{"result_type":"success","tx_id":"tx-1","signature":"Zm9yZ2Vk"}`)
	require.ErrorIs(t, queue.handler(tampered), messaging.ErrPermament)

	_, outsiderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	outsider := testNode{id: "outsider", privateKey: outsiderKey}
	require.ErrorIs(t, queue.handler(signedMessage(t, outsider, subject, success)), messaging.ErrPermament)

	impostor := testNode{id: nodes[1].id, privateKey: outsiderKey}
	require.ErrorIs(t, queue.handler(signedMessage(t, impostor, subject, success)), messaging.ErrPermament)

	require.Empty(t, *delivered)
}

func TestOnSignResultAcksOnlyAfterDelivery(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyEnforce, publicKeys, 2)
	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.Empty(t, queue.settled, "a copy waiting for quorum must stay unacked so a crash redelivers it")
	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, success)))
	require.Len(t, *delivered, 1)
	require.Equal(t, []error{nil, nil}, queue.settled)

	require.NoError(t, queue.handler(signedMessage(t, nodes[2], subject, success)))
	require.Len(t, *delivered, 1)
	require.Len(t, queue.settled, 3)
}

func TestOnSignResultLogModeDeliversOnceWithPerNodeCopies(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyLog, publicKeys, 2)
	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}

	for _, node := range nodes {
		require.NoError(t, queue.handler(signedMessage(t, node, subject, success)))
	}
	require.Len(t, *delivered, 1)
	require.Len(t, queue.settled, 3)
}

func TestOnSignResultUsesWalletThreshold(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, 3)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{
		signResultQueue:                 queue,
		resultVerifier:                  verifier,
		requiredNodeSignaturesForWallet: func(walletID string) int { return map[string]int{"small-wallet": 2}[walletID] },
	}
	var delivered []event.SigningResultEvent
	require.NoError(t, c.OnSignResult(func(e event.SigningResultEvent) { delivered = append(delivered, e) }))

	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "small-wallet", TxID: "tx-1", Signature: []byte("sig")}
	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, success)))
	require.Len(t, delivered, 1)
}

func TestResharingRejectsThresholdAboveNodeKeys(t *testing.T) {
	_, publicKeys := newTestNodes(t, 3)
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, 2)
	require.NoError(t, err)
	c := &mpcClient{resultVerifier: verifier, signer: staticSigner{}, pubsub: &recordingPubSub{}}

	err = c.Resharing(&types.ResharingMessage{SessionID: "session-1", NewThreshold: 3, WalletID: "wallet-1"})
	require.Error(t, err)
}

func TestOnSignResultSubscriptionsShareOneAggregator(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, 2)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{signResultQueue: queue, resultVerifier: verifier}
	var first, second []event.SigningResultEvent
	require.NoError(t, c.OnSignResult(func(e event.SigningResultEvent) { first = append(first, e) }))
	require.NoError(t, c.OnSignResult(func(e event.SigningResultEvent) { second = append(second, e) }))
	require.Len(t, queue.handlers, 2)

	subject := event.SigningResultSubject("")
	success := event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1", Signature: []byte("sig")}
	require.NoError(t, queue.handlers[0](signedMessage(t, nodes[0], subject, success)))
	require.NoError(t, queue.handlers[1](signedMessage(t, nodes[1], subject, success)))
	require.NoError(t, queue.handlers[0](signedMessage(t, nodes[2], subject, success)))

	require.Empty(t, first)
	require.Len(t, second, 1, "copies split across subscriptions must still reach t+1 once")
}

func TestOnSignResultLogModeDeliversUnsignedResults(t *testing.T) {
	_, publicKeys := newTestNodes(t, 3)
	queue, delivered := newSigningResultClient(t, ResultVerifyLog, publicKeys, 2)
	body, err := json.Marshal(event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1"})
	require.NoError(t, err)

	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.Len(t, *delivered, 1)
}

func TestOnSignResultOffDeliversEveryResult(t *testing.T) {
	queue, delivered := newSigningResultClient(t, "", nil, 0)
	body, err := json.Marshal(event.SigningResultEvent{ResultType: event.ResultTypeSuccess, TxID: "tx-1"})
	require.NoError(t, err)

	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.NoError(t, queue.handler(messaging.Message{Subject: event.SigningResultSubject(""), Data: body}))
	require.Len(t, *delivered, 2)
}

func TestOnResharingResultUsesNewCommitteeThreshold(t *testing.T) {
	nodes, publicKeys := newTestNodes(t, 3)
	verifier, err := newResultVerifier(ResultVerifyEnforce, publicKeys, 2)
	require.NoError(t, err)
	queue := &capturingQueue{}
	c := &mpcClient{reshareSuccessQueue: queue, resultVerifier: verifier, signer: staticSigner{}, pubsub: &recordingPubSub{}}
	var delivered []event.ResharingResultEvent
	require.NoError(t, c.OnResharingResult(func(e event.ResharingResultEvent) { delivered = append(delivered, e) }))

	require.NoError(t, c.Resharing(&types.ResharingMessage{SessionID: "session-1", NewThreshold: 2, WalletID: "wallet-1"}))
	subject := event.ReshareResultSubject("", "session-1")
	success := event.ResharingResultEvent{ResultType: event.ResultTypeSuccess, WalletID: "wallet-1", NewThreshold: 2, PubKey: []byte("pub")}

	require.NoError(t, queue.handler(signedMessage(t, nodes[0], subject, success)))
	require.NoError(t, queue.handler(signedMessage(t, nodes[1], subject, success)))
	require.Empty(t, delivered, "new threshold 2 needs 3 matching results")
	require.NoError(t, queue.handler(signedMessage(t, nodes[2], subject, success)))
	require.Len(t, delivered, 1)

	_, stillTracked := c.reshareRequiredSigs.Load(subject)
	require.False(t, stillTracked)
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
