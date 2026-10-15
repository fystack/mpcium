//go:build dkls

package dkls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestKeygenAndSign_3of3(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	sessions := newMemorySessions(t, "wallet-1", nodeIDs, 2)

	keys := runKeygen(t, sessions)
	for _, id := range nodeIDs[1:] {
		if !bytes.Equal(keys[id].PubKey, keys[nodeIDs[0]].PubKey) {
			t.Fatalf("public keys diverge between %s and %s", nodeIDs[0], id)
		}
	}
	if len(keys[nodeIDs[0]].PubKey) != 64 {
		t.Fatalf("public key length = %d, want 64 (tss-lib X||Y format)", len(keys[nodeIDs[0]].PubKey))
	}

	hash := sha256.Sum256([]byte("integration-test"))
	sig := runSign(t, sessions, nodeIDs, hash[:], nil)
	verifySignature(t, sig, hash[:], parsePubKey(t, keys[nodeIDs[0]].PubKey))
}

func TestSign_2of3Subset(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	sessions := newMemorySessions(t, "wallet-2", nodeIDs, 1)
	keys := runKeygen(t, sessions)

	hash := sha256.Sum256([]byte("subset-signing-test"))
	sig := runSign(t, sessions, []string{"node-a", "node-b"}, hash[:], nil)
	verifySignature(t, sig, hash[:], parsePubKey(t, keys["node-a"].PubKey))
}

func TestSign_RejectsSignerSetWithoutSelf(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	sessions := newMemorySessions(t, "wallet-3", nodeIDs, 1)

	hash := sha256.Sum256([]byte("x"))
	if _, err := sessions["node-c"].Sign(hash[:], []string{"node-a", "node-b"}, nil); !errors.Is(err, ErrNotSelected) {
		t.Fatalf("err = %v, want ErrNotSelected", err)
	}
}

func TestNewSession_RejectsNonParticipant(t *testing.T) {
	_, err := NewSession(SessionConfig{SelfNodeID: "node-x", Participants: []string{"node-a", "node-b"}})
	if !errors.Is(err, ErrNotParticipant) {
		t.Fatalf("err = %v, want ErrNotParticipant", err)
	}
}

func TestDerivation_ChildKeyMatchesBIP32AndSigns(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	sessions := newMemorySessions(t, "wallet-hd", nodeIDs, 1)
	keys := runKeygen(t, sessions)
	master := keys["node-a"]
	if len(master.ChainCode) != 32 {
		t.Fatalf("chain code length = %d, want 32", len(master.ChainCode))
	}

	path := []uint32{1, 5}
	childPubs := make(map[string][]byte, len(nodeIDs))
	for id, sess := range sessions {
		pub, err := sess.DerivePublicKey(path)
		if err != nil {
			t.Fatalf("derive public key on %s: %v", id, err)
		}
		childPubs[id] = pub
	}
	for _, id := range nodeIDs[1:] {
		if !bytes.Equal(childPubs[id], childPubs["node-a"]) {
			t.Fatalf("child public keys diverge between node-a and %s", id)
		}
	}
	if bytes.Equal(childPubs["node-a"], master.PubKey) {
		t.Fatal("child public key equals master public key")
	}

	expected := bip32DerivePublic(t, compressXY(t, master.PubKey), master.ChainCode, path)
	expectedXY, err := encodeCompressedPubKey(expected.SerializeCompressed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(childPubs["node-a"], expectedXY) {
		t.Fatal("derived public key does not match BIP-32 CKDpub of master key + chain code")
	}

	signers := []string{"node-a", "node-b"}
	hash := sha256.Sum256([]byte("hd-signing-test"))
	verifySignature(t, runSign(t, sessions, signers, hash[:], path), hash[:], expected)
	verifySignature(t, runSign(t, sessions, signers, hash[:], nil), hash[:], parsePubKey(t, master.PubKey))
}

func TestDerivation_HardenedIndexRejected(t *testing.T) {
	sessions := newMemorySessions(t, "w", []string{"node-a", "node-b"}, 1)
	if _, err := sessions["node-a"].DerivePublicKey([]uint32{hardenedOffset}); err == nil {
		t.Fatal("expected hardened index to be rejected")
	}
}

// Deliberately independent of the library under test.
func bip32DerivePublic(t *testing.T, compressedPub, chainCode []byte, path []uint32) *btcec.PublicKey {
	t.Helper()
	pub, err := btcec.ParsePubKey(compressedPub)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range path {
		mac := hmac.New(sha512.New, chainCode)
		mac.Write(pub.SerializeCompressed())
		mac.Write(binary.BigEndian.AppendUint32(nil, index))
		sum := mac.Sum(nil)

		var tweak btcec.ModNScalar
		if overflow := tweak.SetByteSlice(sum[:32]); overflow {
			t.Fatal("tweak overflow")
		}
		var tweakPoint, parent, child btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&tweak, &tweakPoint)
		pub.AsJacobian(&parent)
		btcec.AddNonConst(&tweakPoint, &parent, &child)
		child.ToAffine()
		pub = btcec.NewPublicKey(&child.X, &child.Y)
		chainCode = sum[32:]
	}
	return pub
}
