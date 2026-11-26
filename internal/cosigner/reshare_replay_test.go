package cosigner

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/fystack/mpcium-sdk/participant"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

const replaySessionID = "reshare-1"

func committedReshareEvent() *sdkprotocol.SessionEvent {
	return &sdkprotocol.SessionEvent{
		SessionID: replaySessionID, ParticipantID: "node-1", Sequence: 7,
		SessionCompleted: &sdkprotocol.SessionCompleted{Result: &sdkprotocol.Result{Reshare: &sdkprotocol.ReshareResult{KeyID: "wallet-1", PublicKey: []byte("pub"), NewThreshold: 1}}},
	}
}

func reshareCommitControl(t *testing.T, signer ed25519.PrivateKey) []byte {
	t.Helper()
	msg := &sdkprotocol.ControlMessage{SessionID: replaySessionID, Sequence: 9, OrchestratorID: "orch-1", ReshareCommit: &sdkprotocol.ReshareCommit{}}
	payload, err := sdkprotocol.ControlSigningBytes(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg.Signature = ed25519.Sign(signer, payload)
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func publishedSessionCompleted(relay *fakeRelay) bool {
	var event sdkprotocol.SessionEvent
	raw, ok := relay.published[sessionEventSubject(replaySessionID)]
	return ok && json.Unmarshal(raw, &event) == nil && event.SessionCompleted != nil
}

// The orchestrator retries a reshare commit until every new member answers; a node that already committed and cleaned up must still answer.
func TestRetriedReshareCommitIsAnsweredAfterCleanup(t *testing.T) {
	stores := &fakeStores{}
	rt, orchPriv, relay := newTestRuntime(t, stores, false)
	if err := stores.SaveCommittedReshare(committedReshareEvent()); err != nil {
		t.Fatal(err)
	}

	if err := rt.handleControl(reshareCommitControl(t, orchPriv)); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionCompleted(relay) {
		t.Fatal("the retried commit was not answered")
	}
}

func TestReshareCommitForAnUnknownSessionIsIgnored(t *testing.T) {
	rt, orchPriv, relay := newTestRuntime(t, &fakeStores{}, false)
	if err := rt.handleControl(reshareCommitControl(t, orchPriv)); err != nil {
		t.Fatal(err)
	}
	if len(relay.published) != 0 {
		t.Fatalf("published %d messages for an unknown session", len(relay.published))
	}
}

func TestCommittedReshareReplayNeedsTheOrchestratorSignature(t *testing.T) {
	stores := &fakeStores{}
	rt, _, relay := newTestRuntime(t, stores, false)
	if err := stores.SaveCommittedReshare(committedReshareEvent()); err != nil {
		t.Fatal(err)
	}
	_, forger, _ := ed25519.GenerateKey(nil)

	if err := rt.handleControl(reshareCommitControl(t, forger)); err == nil {
		t.Fatal("a commit not signed by the orchestrator was accepted")
	}
	if len(relay.published) != 0 {
		t.Fatal("a forged commit was answered")
	}
}

func TestCommittingAReshareKeepsItsCompletionForRetries(t *testing.T) {
	stores := &fakeStores{}
	rt, _, _ := newTestRuntime(t, stores, false)
	completed := committedReshareEvent()

	err := rt.dispatchActions(participant.Actions{
		SessionEvents: []*sdkprotocol.SessionEvent{completed},
		Result:        completed.SessionCompleted.Result,
		Cleanup:       &participant.CleanupHint{SessionID: replaySessionID, DropCheckpoint: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if kept, _ := stores.LoadCommittedReshare(replaySessionID); kept == nil {
		t.Fatal("the committed reshare's completion was not kept")
	}
}
