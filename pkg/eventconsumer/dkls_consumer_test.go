//go:build dkls

package eventconsumer

import (
	"testing"
	"time"
)

func TestSessionTracker_DropsDuplicatesUntilReleasedOrExpired(t *testing.T) {
	tracker := newSessionTracker(50 * time.Millisecond)

	if !tracker.begin("w:tx1") {
		t.Fatal("first request must be accepted")
	}
	if tracker.begin("w:tx1") {
		t.Fatal("duplicate while in flight or recently done must be rejected")
	}

	tracker.release("w:tx1")
	if !tracker.begin("w:tx1") {
		t.Fatal("released request must be accepted again (retry after failure)")
	}

	time.Sleep(80 * time.Millisecond)
	if !tracker.begin("w:tx1") {
		t.Fatal("request must be accepted again after the TTL")
	}
}

func TestSessionTracker_SweepBoundsMemory(t *testing.T) {
	tracker := newSessionTracker(20 * time.Millisecond)
	for i := range 100 {
		tracker.begin(string(rune('a' + i)))
	}
	time.Sleep(60 * time.Millisecond)
	tracker.begin("fresh")

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.seen) != 1 {
		t.Fatalf("tracker kept %d entries after the TTL, want 1", len(tracker.seen))
	}
}
