package types

import (
	"bytes"
	"reflect"
	"testing"
)

func TestDklsMessageWireRoundTrip(t *testing.T) {
	in := DklsMessage{
		From:      "node-a",
		Phase:     3,
		Payload:   bytes.Repeat([]byte{0xAB}, 70000),
		Signature: []byte("signature"),
	}
	var out DklsMessage
	if err := out.UnmarshalWire(in.MarshalWire()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatal("round trip mismatch")
	}
}

func TestDklsMessageWireRejectsTruncated(t *testing.T) {
	in := DklsMessage{From: "a", Phase: 1, Payload: []byte{1, 2, 3}, Signature: []byte{9}}
	wire := in.MarshalWire()
	for n := 0; n < len(wire); n++ {
		var out DklsMessage
		if err := out.UnmarshalWire(wire[:n]); err == nil {
			t.Fatalf("expected error for %d-byte prefix", n)
		}
	}
}

func TestDklsMessageSigningBytesBindRouteAndRecipient(t *testing.T) {
	base := DklsMessage{Route: "sign.w:tx1", To: "node-b", From: "node-a", Phase: 1, Payload: []byte("p")}
	baseBytes, _ := base.MarshalForSigning()

	for name, mutate := range map[string]func(*DklsMessage){
		"route":   func(m *DklsMessage) { m.Route = "sign.w:tx2" },
		"to":      func(m *DklsMessage) { m.To = "node-c" },
		"from":    func(m *DklsMessage) { m.From = "node-x" },
		"phase":   func(m *DklsMessage) { m.Phase = 2 },
		"payload": func(m *DklsMessage) { m.Payload = []byte("q") },
	} {
		changed := base
		mutate(&changed)
		if got, _ := changed.MarshalForSigning(); bytes.Equal(got, baseBytes) {
			t.Fatalf("signing bytes do not cover %s", name)
		}
	}

	withSig := base
	withSig.Signature = []byte("sig")
	if got, _ := withSig.MarshalForSigning(); !bytes.Equal(got, baseBytes) {
		t.Fatal("signing bytes must not depend on the signature")
	}
}
