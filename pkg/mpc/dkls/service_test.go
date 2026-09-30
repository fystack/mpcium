//go:build dkls

package dkls

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/messaging"
)

func newTestServices(t testing.TB, bus messaging.PubSub, nodeIDs []string, ready []string) map[string]*Service {
	t.Helper()
	identities := newTestIdentities(nodeIDs)
	services := make(map[string]*Service, len(nodeIDs))
	for _, id := range nodeIDs {
		store := newFakeStore()
		svc, err := NewService(Config{
			NodeID:   id,
			PubSub:   bus,
			Identity: identities[id],
			KV:       store,
			KeyInfo:  keyInfoView{store},
			Peers:    fakePeers{ready: ready},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(svc.Close)
		services[id] = svc
	}
	return services
}

func TestService_KeygenAndSignOverPubSub(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	services := newTestServices(t, &fakePubSub{}, nodeIDs, nodeIDs)

	type keygenResult struct {
		res KeyResult
		err error
	}
	kgCh := make(chan keygenResult, len(nodeIDs))
	for _, svc := range services {
		go func() {
			res, err := svc.Keygen("wallet-svc", 1)
			kgCh <- keygenResult{res, err}
		}()
	}
	var master KeyResult
	for range nodeIDs {
		r := <-kgCh
		if r.err != nil {
			t.Fatalf("keygen: %v", r.err)
		}
		master = r.res
	}

	hash := sha256.Sum256([]byte("service-sign"))
	type signResult struct {
		sig Signature
		err error
	}
	signCh := make(chan signResult, len(nodeIDs))
	for _, id := range nodeIDs[:2] {
		go func() {
			sig, err := services[id].Sign("wallet-svc", "tx-1", hash[:], []uint32{7})
			signCh <- signResult{sig, err}
		}()
	}
	var sig Signature
	for range nodeIDs[:2] {
		r := <-signCh
		if r.err != nil && !errors.Is(r.err, ErrNotSelected) {
			t.Fatalf("sign: %v", r.err)
		}
		if r.err == nil {
			sig = r.sig
		}
	}

	child := bip32DerivePublic(t, compressXY(t, master.PubKey), master.ChainCode, []uint32{7})
	verifySignature(t, sig, hash[:], child)
}

func TestService_SignErrors(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	hash := sha256.Sum256([]byte("x"))

	t.Run("unknown wallet", func(t *testing.T) {
		svc := newTestServices(t, &fakePubSub{}, nodeIDs[:1], nodeIDs)["node-a"]
		if _, err := svc.Sign("nope", "tx", hash[:], nil); !errors.Is(err, ErrWalletNotFound) {
			t.Fatalf("err = %v, want ErrWalletNotFound", err)
		}
	})

	seed := func(svc *Service, participants []string, threshold int) {
		if err := svc.keys.Save("w", []byte("share"), &keyinfo.KeyInfo{ParticipantPeerIDs: participants, Threshold: threshold, Version: 1}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("node is not a participant", func(t *testing.T) {
		svc := newTestServices(t, &fakePubSub{}, nodeIDs[:1], nodeIDs)["node-a"]
		seed(svc, []string{"node-b", "node-c"}, 1)
		if _, err := svc.Sign("w", "tx", hash[:], nil); !errors.Is(err, ErrNotParticipant) {
			t.Fatalf("err = %v, want ErrNotParticipant", err)
		}
	})

	t.Run("too few ready participants retries later", func(t *testing.T) {
		svc := newTestServices(t, &fakePubSub{}, nodeIDs[:1], []string{"node-a"})["node-a"]
		seed(svc, nodeIDs, 1)
		if _, err := svc.Sign("w", "tx", hash[:], nil); !errors.Is(err, ErrNotEnoughSigners) {
			t.Fatalf("err = %v, want ErrNotEnoughSigners", err)
		}
	})

	t.Run("node outside the selected signer set", func(t *testing.T) {
		svc := newTestServices(t, &fakePubSub{}, nodeIDs[2:], nodeIDs)["node-c"]
		seed(svc, nodeIDs, 1)
		if _, err := svc.Sign("w", "tx", hash[:], nil); !errors.Is(err, ErrNotSelected) {
			t.Fatalf("err = %v, want ErrNotSelected", err)
		}
	})
}
