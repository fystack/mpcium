//go:build dkls

package dkls

import (
	"strings"
	"testing"
	"time"

	dklsll "github.com/fystack/DKLs23/wrapper/go-ll/dkls"
	"github.com/fystack/mpcium/pkg/types"
)

func newTestRound(t *testing.T) (*round, *memoryTransport) {
	t.Helper()
	nodeIDs := []string{"node-a", "node-b"}
	transport := newMemoryCluster(nodeIDs)["node-a"]
	_, partyIDs := assignPartyIDs(nodeIDs)
	return newRound("node-a", partyIDs["node-a"], partyIDs, transport, sharedTestKeys(nodeIDs)["node-a"]), transport
}

func broadcastBundle(payload string, kind dklsll.MessageKind) []byte {
	return encodeBundle([]dklsll.Message{{FromID: 2, ToID: broadcastToID, Kind: kind, Payload: []byte(payload)}})
}

func TestRound_BuffersBundlesFromLaterPhase(t *testing.T) {
	r, transport := newTestRound(t)
	transport.inbox <- types.DklsMessage{From: "node-b", Phase: uint8(PhaseSG2), Payload: broadcastBundle("two", dklsll.MsgSignPhase2)}
	transport.inbox <- types.DklsMessage{From: "node-b", Phase: uint8(PhaseSG1), Payload: broadcastBundle("one", dklsll.MsgSignPhase1)}

	got1, err := r.receive(PhaseSG1, []string{"node-b"})
	if err != nil || len(got1) != 1 || string(got1[0].Payload) != "one" {
		t.Fatalf("phase 1: %v %v", got1, err)
	}
	got2, err := r.receive(PhaseSG2, []string{"node-b"})
	if err != nil || len(got2) != 1 || string(got2[0].Payload) != "two" {
		t.Fatalf("phase 2 (buffered): %v %v", got2, err)
	}
}

func TestRound_IgnoresDuplicateAndUnexpectedSenders(t *testing.T) {
	r, transport := newTestRound(t)
	bundle := broadcastBundle("one", dklsll.MsgSignPhase1)
	transport.inbox <- types.DklsMessage{From: "node-b", Phase: uint8(PhaseSG1), Payload: bundle}
	transport.inbox <- types.DklsMessage{From: "node-b", Phase: uint8(PhaseSG1), Payload: bundle}
	transport.inbox <- types.DklsMessage{From: "node-z", Phase: uint8(PhaseSG1), Payload: bundle}

	got, err := r.receive(PhaseSG1, []string{"node-b"})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d messages, err %v; want exactly the one expected bundle", len(got), err)
	}
}

func TestRound_TimesOutWhenPeerIsSilent(t *testing.T) {
	r, _ := newTestRound(t)
	r.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := r.receive(PhaseSG1, []string{"node-b"})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("receive did not honor the round timeout")
	}
}
