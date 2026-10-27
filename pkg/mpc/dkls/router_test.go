//go:build dkls

package dkls

import (
	"testing"
	"time"

	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

func newTestRouters(t *testing.T, bus *fakePubSub, nodeIDs []string) (map[string]*Router, map[string]ed25519Authenticator) {
	t.Helper()
	auths := newEd25519Authenticators(nodeIDs)
	routers := make(map[string]*Router, len(nodeIDs))
	for _, id := range nodeIDs {
		r, err := NewRouter(id, bus, auths[id])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Close)
		routers[id] = r
	}
	return routers, auths
}

func receiveWithin(t *testing.T, inbox <-chan types.DklsMessage, d time.Duration) (types.DklsMessage, bool) {
	t.Helper()
	select {
	case msg := <-inbox:
		return msg, true
	case <-time.After(d):
		return types.DklsMessage{}, false
	}
}

func TestRouter_DeliversVerifiedBundleAndBuffersEarlyOnes(t *testing.T) {
	bus := &fakePubSub{}
	nodeIDs := []string{"node-a", "node-b"}
	routers, auths := newTestRouters(t, bus, nodeIDs)

	sender := NewNATSTransport("w:tx1", ActSign, routers["node-a"], bus, auths["node-a"])
	if err := sender.Send("node-b", types.DklsMessage{From: "node-a", Phase: 1, Payload: []byte("early")}); err != nil {
		t.Fatal(err)
	}

	receiver := NewNATSTransport("w:tx1", ActSign, routers["node-b"], bus, auths["node-b"])
	msg, ok := receiveWithin(t, receiver.Inbox(), time.Second)
	if !ok || string(msg.Payload) != "early" {
		t.Fatalf("early bundle was not delivered after the session registered: %v %v", msg, ok)
	}
}

func TestRouter_RejectsBundleReplayedOnAnotherSession(t *testing.T) {
	bus := &fakePubSub{}
	routers, auths := newTestRouters(t, bus, []string{"node-a", "node-b"})

	var captured []byte
	tap, _ := bus.Subscribe(sessionSubject("node-b", ActSign, "w:tx1"), func(m *nats.Msg) { captured = m.Data })
	defer tap.Unsubscribe()

	sender := NewNATSTransport("w:tx1", ActSign, routers["node-a"], bus, auths["node-a"])
	if err := sender.Send("node-b", types.DklsMessage{From: "node-a", Phase: 1, Payload: []byte("real")}); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("did not capture the wire message")
	}

	victim := NewNATSTransport("w:tx2", ActSign, routers["node-b"], bus, auths["node-b"])
	if err := bus.Publish(sessionSubject("node-b", ActSign, "w:tx2"), captured, nil); err != nil {
		t.Fatal(err)
	}
	if msg, ok := receiveWithin(t, victim.Inbox(), 200*time.Millisecond); ok {
		t.Fatalf("replayed bundle was accepted on another session: %v", msg)
	}
}
