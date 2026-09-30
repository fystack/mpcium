//go:build dkls

// Package dkls is the opt-in DKLs23 threshold-ECDSA backend (Rust via cgo, build tag dkls).
package dkls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	dklsll "github.com/fystack/DKLs23/wrapper/go-ll/dkls"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/keyinfo"
)

var (
	ErrNotEnoughSigners = errors.New("not enough ready participants to sign")
	ErrNotParticipant   = errors.New("node is not a participant of this wallet")
	ErrNotSelected      = errors.New("node is not in the selected signer set")
	ErrWalletNotFound   = errors.New("dkls wallet not found")
	ErrKeyExists        = errors.New("dkls key already exists")
	ErrPeersNotReady    = errors.New("not all peers are ready")
)

type Signature = dklsll.Signature

type KeyResult struct {
	PubKey    []byte // 64-byte X||Y, the tss-lib ECDSA key format
	ChainCode []byte
}

type SessionConfig struct {
	WalletID     string
	SelfNodeID   string
	Participants []string
	Threshold    int    // t; t+1 signers are required
	SessionKey   string // keeps sign IDs unique per request
	Transport    Transport
	Cipher       MessageCipher
	Keys         KeyShareStore
}

type Session struct {
	cfg          SessionConfig
	participants []string
	partyIDs     map[string]uint8
	self         uint8
	round        *round
}

func NewSession(cfg SessionConfig) (*Session, error) {
	participants, partyIDs := assignPartyIDs(cfg.Participants)
	self, ok := partyIDs[cfg.SelfNodeID]
	if !ok {
		return nil, ErrNotParticipant
	}
	return &Session{
		cfg:          cfg,
		participants: participants,
		partyIDs:     partyIDs,
		self:         self,
		round:        newRound(cfg.SelfNodeID, self, partyIDs, cfg.Transport, cfg.Cipher),
	}, nil
}

func (s *Session) Close() error { return s.cfg.Transport.Close() }

func (s *Session) peersOf(nodeIDs []string) []string {
	return slices.DeleteFunc(slices.Clone(nodeIDs), func(id string) bool { return id == s.cfg.SelfNodeID })
}

func sessionID(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

func (s *Session) Keygen() (KeyResult, error) {
	peers := s.peersOf(s.participants)
	id := sessionID(append([]string{"dkls-dkg", s.cfg.WalletID, strconv.Itoa(s.cfg.Threshold)}, s.participants...)...)

	dkg, err := dklsll.NewDkgSession(uint8(s.cfg.Threshold+1), uint8(len(s.participants)), s.self, id)
	if err != nil {
		return KeyResult{}, fmt.Errorf("new dkg session: %w", err)
	}
	defer dkg.Free()

	out1, err := dkg.Phase1()
	if err != nil {
		return KeyResult{}, fmt.Errorf("dkg phase1: %w", err)
	}
	all1, err := s.round.exchange(PhaseKG1, out1, peers)
	if err != nil {
		return KeyResult{}, err
	}

	out2, err := dkg.Phase2(ofKind(all1, dklsll.MsgPolyFragment, s.self))
	if err != nil {
		return KeyResult{}, fmt.Errorf("dkg phase2: %w", err)
	}
	all2, err := s.round.exchange(PhaseKG2, out2, peers)
	if err != nil {
		return KeyResult{}, err
	}

	out3, err := dkg.Phase3()
	if err != nil {
		return KeyResult{}, fmt.Errorf("dkg phase3: %w", err)
	}
	all3, err := s.round.exchange(PhaseKG3, out3, peers)
	if err != nil {
		return KeyResult{}, err
	}

	incoming := addressedTo(all3, s.self)
	incoming = append(incoming, ofKind(all2, dklsll.MsgDkgZeroP2, s.self)...)
	incoming = append(incoming, broadcasts(all2)...)
	party, err := dkg.Phase4(incoming)
	if err != nil {
		return KeyResult{}, fmt.Errorf("dkg phase4: %w", err)
	}
	defer party.Free()

	share, err := party.ToBytes()
	if err != nil {
		return KeyResult{}, fmt.Errorf("serialize key share: %w", err)
	}
	pubKey, err := partyPubKey(party)
	if err != nil {
		return KeyResult{}, err
	}
	chainCode, err := party.ChainCode()
	if err != nil {
		return KeyResult{}, fmt.Errorf("get chain code: %w", err)
	}

	info := &keyinfo.KeyInfo{ParticipantPeerIDs: s.participants, Threshold: s.cfg.Threshold, Version: 1}
	if err := s.cfg.Keys.Save(s.cfg.WalletID, share, info); err != nil {
		return KeyResult{}, err
	}
	return KeyResult{PubKey: pubKey, ChainCode: chainCode}, nil
}

func (s *Session) Sign(msgHash []byte, signers []string, derivationPath []uint32) (Signature, error) {
	signers = sortedCopy(signers)
	if !slices.Contains(signers, s.cfg.SelfNodeID) {
		return Signature{}, ErrNotSelected
	}

	party, err := s.loadParty(derivationPath)
	if err != nil {
		return Signature{}, err
	}
	defer party.Free()

	peers := s.peersOf(signers)
	counterparties := make([]uint8, len(peers))
	for i, peer := range peers {
		counterparties[i] = s.partyIDs[peer]
	}

	id := sessionID(append([]string{"dkls-sign", s.cfg.WalletID, s.cfg.SessionKey, derivationPathLabel(derivationPath)}, signers...)...)
	sess, err := dklsll.NewSignSession(party, id, counterparties, msgHash)
	if err != nil {
		return Signature{}, fmt.Errorf("new sign session: %w", err)
	}
	defer sess.Free()

	out1, err := sess.Phase1()
	if err != nil {
		return Signature{}, fmt.Errorf("sign phase1: %w", err)
	}
	all1, err := s.round.exchange(PhaseSG1, out1, peers)
	if err != nil {
		return Signature{}, err
	}

	out2, err := sess.Phase2(ofKind(all1, dklsll.MsgSignPhase1, s.self))
	if err != nil {
		return Signature{}, fmt.Errorf("sign phase2: %w", err)
	}
	all2, err := s.round.exchange(PhaseSG2, out2, peers)
	if err != nil {
		return Signature{}, err
	}

	out3, err := sess.Phase3(ofKind(all2, dklsll.MsgSignPhase2, s.self))
	if err != nil {
		return Signature{}, fmt.Errorf("sign phase3: %w", err)
	}
	all3, err := s.round.exchange(PhaseSG3, out3, peers)
	if err != nil {
		return Signature{}, err
	}

	raw, err := sess.Phase4(broadcastsOfKind(all3, dklsll.MsgSignBroadcast), true)
	if err != nil {
		return Signature{}, fmt.Errorf("sign phase4: %w", err)
	}
	return dklsll.ParseSignature(raw)
}

func sortedCopy(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

const hardenedOffset = 0x80000000

// Only non-hardened indices work: no party holds the full key.
func (s *Session) loadParty(derivationPath []uint32) (*dklsll.Party, error) {
	for _, index := range derivationPath {
		if index >= hardenedOffset {
			return nil, fmt.Errorf("hardened derivation index %d is not supported by dkls23", index)
		}
	}
	share, err := s.cfg.Keys.LoadShare(s.cfg.WalletID)
	if err != nil {
		return nil, fmt.Errorf("load key share: %w", err)
	}
	party, err := dklsll.PartyFromBytes(share)
	if err != nil {
		return nil, fmt.Errorf("deserialize key share: %w", err)
	}
	if len(derivationPath) == 0 {
		return party, nil
	}
	defer party.Free()
	child, err := party.Derive(derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive child share: %w", err)
	}
	return child, nil
}

func (s *Session) DerivePublicKey(derivationPath []uint32) ([]byte, error) {
	party, err := s.loadParty(derivationPath)
	if err != nil {
		return nil, err
	}
	defer party.Free()
	return partyPubKey(party)
}

func partyPubKey(party *dklsll.Party) ([]byte, error) {
	compressed, err := party.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	return encodeCompressedPubKey(compressed)
}

func encodeCompressedPubKey(compressed []byte) ([]byte, error) {
	pub, err := btcec.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("parse compressed public key: %w", err)
	}
	return encoding.EncodeS256PubKey(pub.ToECDSA())
}

func derivationPathLabel(path []uint32) string {
	if len(path) == 0 {
		return ""
	}
	return fmt.Sprint(path)
}

// Sorting makes every node compute the same party IDs without coordination.
func assignPartyIDs(nodeIDs []string) (sorted []string, partyIDs map[string]uint8) {
	sorted = append([]string(nil), nodeIDs...)
	sort.Strings(sorted)

	partyIDs = make(map[string]uint8, len(sorted))
	for i, id := range sorted {
		partyIDs[id] = uint8(i + 1)
	}
	return sorted, partyIDs
}
