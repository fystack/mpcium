package mpc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/fystack/mpcium/pkg/types"
)

// NonceDomain is a domain-separation tag folded into a session nonce so a nonce
// derived for one ceremony type can never be valid in another.
type NonceDomain string

const (
	NonceDomainKeygen  NonceDomain = "mpcium/ssid-nonce/keygen/v1"
	NonceDomainSigning NonceDomain = "mpcium/ssid-nonce/signing/v1"
	NonceDomainReshare NonceDomain = "mpcium/ssid-nonce/reshare/v1"
)

// nonceFieldSep separates the domain tag from the initiator payload in the hash
// input. 0x1f (unit separator) cannot appear in a domain tag.
var nonceFieldSep = []byte{0x1f}

// ErrNilSessionNonce is returned when a session is built without the nonce that
// GG20 session binding requires.
var ErrNilSessionNonce = errors.New("session nonce is required")

// SessionNonceFromInitiator derives the per-ceremony nonce that tss-lib v3 mixes
// into the SSID of every ZK proof, binding the proofs to this exact ceremony and
// preventing cross-session proof replay.
//
// It is SHA-256(domain || 0x1f || initiatorPayload), where initiatorPayload is
// the exact byte string the initiator signed (msg.Raw()). Every node
// independently verifies the same signed request, so every node derives an
// identical nonce with no extra coordination round; the domain tag keeps keygen,
// signing and resharing nonces disjoint.
//
// Per-ceremony uniqueness comes from the initiator payload:
//   - keygen:  the wallet ID
//   - signing: key type + wallet ID + network + tx ID + tx + derivation path
//   - reshare: the full resharing request, including its session ID
//
// Note: a keygen retried for the same wallet ID re-derives the same nonce. That
// still binds proofs across distinct concurrent ceremonies (the property GG20
// needs); strict per-attempt uniqueness would require a nonce field in the
// signed keygen request.
func SessionNonceFromInitiator(domain NonceDomain, msg types.InitiatorMessage) (*big.Int, error) {
	if msg == nil {
		return nil, errors.New("session nonce: initiator message is nil")
	}
	raw, err := msg.Raw()
	if err != nil {
		return nil, fmt.Errorf("session nonce: read initiator payload: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(nonceFieldSep)
	h.Write(raw)
	// Positive 256-bit integer. tss-lib only hashes this value into the SSID, so
	// there is no curve-order bound to respect.
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// newTSSParameters builds tss-lib parameters with the session nonce applied.
// The nonce is mandatory: keygen and signing proofs must be session-bound.
func newTSSParameters(
	ec elliptic.Curve,
	ctx *tss.PeerContext,
	partyID *tss.PartyID,
	partyCount, threshold int,
	sessionNonce *big.Int,
) (*tss.Parameters, error) {
	if sessionNonce == nil {
		return nil, ErrNilSessionNonce
	}
	params := tss.NewParameters(ec, ctx, partyID, partyCount, threshold)
	params.SetSessionNonce(sessionNonce)
	return params, nil
}

// newTSSReSharingParameters is newTSSParameters for a resharing ceremony.
func newTSSReSharingParameters(
	ec elliptic.Curve,
	ctx, newCtx *tss.PeerContext,
	partyID *tss.PartyID,
	partyCount, threshold, newPartyCount, newThreshold int,
	sessionNonce *big.Int,
) (*tss.ReSharingParameters, error) {
	if sessionNonce == nil {
		return nil, ErrNilSessionNonce
	}
	params := tss.NewReSharingParameters(ec, ctx, newCtx, partyID, partyCount, threshold, newPartyCount, newThreshold)
	params.SetSessionNonce(sessionNonce)
	return params, nil
}
