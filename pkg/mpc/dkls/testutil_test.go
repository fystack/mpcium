//go:build dkls

package dkls

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

var errNotFound = errors.New("not found")

type testCipher struct {
	keys map[string][]byte
}

func (c testCipher) EncryptMessage(plaintext []byte, peerID string) ([]byte, error) {
	return encryption.EncryptAESGCMWithNonceEmbed(plaintext, c.keys[peerID])
}

func (c testCipher) DecryptMessage(cipher []byte, peerID string) ([]byte, error) {
	return encryption.DecryptAESGCMWithNonceEmbed(cipher, c.keys[peerID])
}

func sharedTestKeys(nodeIDs []string) map[string]testCipher {
	keys := make(map[string]map[string][]byte, len(nodeIDs))
	for _, id := range nodeIDs {
		keys[id] = make(map[string][]byte, len(nodeIDs)-1)
	}
	for i, a := range nodeIDs {
		for _, b := range nodeIDs[i+1:] {
			h := sha256.Sum256([]byte("test-pair-key:" + a + ":" + b))
			keys[a][b] = h[:]
			keys[b][a] = h[:]
		}
	}
	ciphers := make(map[string]testCipher, len(nodeIDs))
	for id, k := range keys {
		ciphers[id] = testCipher{keys: k}
	}
	return ciphers
}

type ed25519Authenticator struct {
	privKey    ed25519.PrivateKey
	publicKeys map[string]ed25519.PublicKey
}

func (a ed25519Authenticator) SignDklsMessage(msg *types.DklsMessage) ([]byte, error) {
	b, err := msg.MarshalForSigning()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(a.privKey, b), nil
}

func (a ed25519Authenticator) VerifyDklsMessage(msg *types.DklsMessage) error {
	pub, ok := a.publicKeys[msg.From]
	if !ok {
		return fmt.Errorf("unknown sender %s", msg.From)
	}
	b, err := msg.MarshalForSigning()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, msg.Signature) {
		return fmt.Errorf("invalid signature from %s", msg.From)
	}
	return nil
}

func newEd25519Authenticators(nodeIDs []string) map[string]ed25519Authenticator {
	pubKeys := make(map[string]ed25519.PublicKey, len(nodeIDs))
	privKeys := make(map[string]ed25519.PrivateKey, len(nodeIDs))
	for _, id := range nodeIDs {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		pubKeys[id], privKeys[id] = pub, priv
	}
	auths := make(map[string]ed25519Authenticator, len(nodeIDs))
	for _, id := range nodeIDs {
		auths[id] = ed25519Authenticator{privKey: privKeys[id], publicKeys: pubKeys}
	}
	return auths
}

type testIdentity struct {
	ed25519Authenticator
	testCipher
}

func newTestIdentities(nodeIDs []string) map[string]testIdentity {
	auths, ciphers := newEd25519Authenticators(nodeIDs), sharedTestKeys(nodeIDs)
	ids := make(map[string]testIdentity, len(nodeIDs))
	for _, id := range nodeIDs {
		ids[id] = testIdentity{auths[id], ciphers[id]}
	}
	return ids
}

type fakeStore struct {
	mu    sync.Mutex
	data  map[string][]byte
	infos map[string]*keyinfo.KeyInfo
}

func newFakeStore() *fakeStore {
	return &fakeStore{data: make(map[string][]byte), infos: make(map[string]*keyinfo.KeyInfo)}
}

func (f *fakeStore) Put(key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeStore) Get(key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return nil, errNotFound
	}
	return v, nil
}

func (f *fakeStore) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

func (f *fakeStore) Close() error  { return nil }
func (f *fakeStore) Backup() error { return nil }

func (f *fakeStore) Save(walletID string, info *keyinfo.KeyInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.infos[walletID] = info
	return nil
}

func (f *fakeStore) GetKeyInfo(walletID string) (*keyinfo.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.infos[walletID]
	if !ok {
		return nil, errNotFound
	}
	return info, nil
}

// keyinfo.Store.Get clashes with kvstore.KVStore.Get, so fakeStore needs this view.
type keyInfoView struct{ *fakeStore }

func (v keyInfoView) Get(walletID string) (*keyinfo.KeyInfo, error) { return v.GetKeyInfo(walletID) }

func newTestKeys() KeyShareStore {
	store := newFakeStore()
	return NewKeyStore(store, keyInfoView{store})
}

type memoryTransport struct {
	selfID string
	peers  map[string]*memoryTransport
	inbox  chan types.DklsMessage
}

func newMemoryCluster(nodeIDs []string) map[string]*memoryTransport {
	transports := make(map[string]*memoryTransport, len(nodeIDs))
	for _, id := range nodeIDs {
		transports[id] = &memoryTransport{selfID: id, peers: transports, inbox: make(chan types.DklsMessage, 256)}
	}
	return transports
}

func (m *memoryTransport) Send(to string, msg types.DklsMessage) error {
	msg.From = m.selfID
	m.peers[to].inbox <- msg
	return nil
}

func (m *memoryTransport) Inbox() <-chan types.DklsMessage { return m.inbox }
func (m *memoryTransport) Close() error                    { return nil }

func newMemorySessions(t *testing.T, walletID string, nodeIDs []string, threshold int) map[string]*Session {
	t.Helper()
	transports := newMemoryCluster(nodeIDs)
	ciphers := sharedTestKeys(nodeIDs)
	sessions := make(map[string]*Session, len(nodeIDs))
	for _, id := range nodeIDs {
		sess, err := NewSession(SessionConfig{
			WalletID:     walletID,
			SelfNodeID:   id,
			Participants: nodeIDs,
			Threshold:    threshold,
			Transport:    transports[id],
			Cipher:       ciphers[id],
			Keys:         newTestKeys(),
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = sess
	}
	return sessions
}

type fakePubSub struct {
	mu   sync.Mutex
	subs []*fakeSub
}

type fakeSub struct {
	pattern string
	handler func(*nats.Msg)
	bus     *fakePubSub
}

func (s *fakeSub) Unsubscribe() error {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	for i, sub := range s.bus.subs {
		if sub == s {
			s.bus.subs = append(s.bus.subs[:i], s.bus.subs[i+1:]...)
			break
		}
	}
	return nil
}

func (b *fakePubSub) Publish(topic string, message []byte, _ map[string]string) error {
	b.mu.Lock()
	var handlers []func(*nats.Msg)
	for _, sub := range b.subs {
		if sub.pattern == topic || (strings.HasSuffix(sub.pattern, ">") && strings.HasPrefix(topic, strings.TrimSuffix(sub.pattern, ">"))) {
			handlers = append(handlers, sub.handler)
		}
	}
	b.mu.Unlock()
	for _, h := range handlers {
		h(&nats.Msg{Subject: topic, Data: message})
	}
	return nil
}

func (b *fakePubSub) PublishWithReply(topic, _ string, data []byte, headers map[string]string) error {
	return b.Publish(topic, data, headers)
}

func (b *fakePubSub) Subscribe(topic string, handler func(*nats.Msg)) (messaging.Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sub := &fakeSub{pattern: topic, handler: handler, bus: b}
	b.subs = append(b.subs, sub)
	return sub, nil
}

type fakePeers struct{ ready []string }

func (p fakePeers) ArePeersReady() bool                { return true }
func (p fakePeers) GetReadyPeersIncludeSelf() []string { return p.ready }

func runKeygen(t *testing.T, sessions map[string]*Session) map[string]KeyResult {
	t.Helper()
	type result struct {
		id  string
		res KeyResult
		err error
	}
	ch := make(chan result, len(sessions))
	for id, sess := range sessions {
		go func() {
			res, err := sess.Keygen()
			ch <- result{id, res, err}
		}()
	}
	out := make(map[string]KeyResult, len(sessions))
	for range sessions {
		r := <-ch
		if r.err != nil {
			t.Fatalf("keygen failed for %s: %v", r.id, r.err)
		}
		out[r.id] = r.res
	}
	return out
}

func runSign(t *testing.T, sessions map[string]*Session, signers []string, hash []byte, path []uint32) Signature {
	t.Helper()
	type result struct {
		sig Signature
		err error
	}
	ch := make(chan result, len(signers))
	for _, id := range signers {
		go func() {
			sig, err := sessions[id].Sign(hash, signers, path)
			ch <- result{sig, err}
		}()
	}
	var first Signature
	for i := range signers {
		r := <-ch
		if r.err != nil {
			t.Fatalf("sign failed: %v", r.err)
		}
		if i == 0 {
			first = r.sig
		} else if r.sig != first {
			t.Fatal("signers produced different signatures")
		}
	}
	return first
}

func compressXY(t *testing.T, xy []byte) []byte {
	t.Helper()
	if len(xy) != 64 {
		t.Fatalf("public key length = %d, want 64", len(xy))
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02 | (xy[63] & 1)
	copy(compressed[1:], xy[:32])
	return compressed
}

func parsePubKey(t *testing.T, xy []byte) *btcec.PublicKey {
	t.Helper()
	pub, err := btcec.ParsePubKey(compressXY(t, xy))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func verifySignature(t *testing.T, sig Signature, hash []byte, pub *btcec.PublicKey) {
	t.Helper()
	var r, s btcec.ModNScalar
	r.SetBytes(&sig.R)
	s.SetBytes(&sig.S)
	if !btcecdsa.NewSignature(&r, &s).Verify(hash, pub) {
		t.Fatal("signature does not verify against the expected public key")
	}
	compact := append([]byte{27 + 4 + sig.Recovery}, sig.R[:]...)
	compact = append(compact, sig.S[:]...)
	recovered, _, err := btcecdsa.RecoverCompact(compact, hash)
	if err != nil {
		t.Fatalf("recover public key: %v", err)
	}
	if !recovered.IsEqual(pub) {
		t.Fatal("recovery id does not recover the signing public key")
	}
}
