package mpc

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/google/uuid"
)

// generatePartyIDs generates the party IDs for the given purpose and version
// It returns the self party ID and all party IDs
// It also sorts the party IDs in place
func (n *Node) generatePartyIDs(
	label string,
	readyPeerIDs []string,
	version int,
) (self *tss.PartyID, all []*tss.PartyID) {
	// Pre-allocate slice with exact size needed
	partyIDs := make([]*tss.PartyID, 0, len(readyPeerIDs))

	// Create all party IDs in one pass
	for _, peerID := range readyPeerIDs {
		partyID := createPartyID(peerID, label, version)
		if peerID == n.nodeID {
			self = partyID
		}
		partyIDs = append(partyIDs, partyID)
	}

	// Sort party IDs in place
	all = tss.SortPartyIDs(partyIDs, 0)
	return
}

// createPartyID creates a new party ID for the given node ID, label and version
// It returns the party ID: random string
// Moniker: for routing messages
// Key: for mpc internal use (need persistent storage)
func createPartyID(nodeID string, label string, version int) *tss.PartyID {
	partyID := uuid.NewString()
	var key *big.Int
	if version == BackwardCompatibleVersion {
		key = new(big.Int).SetBytes([]byte(nodeID))
	} else {
		key = new(big.Int).SetBytes([]byte(fmt.Sprintf("%s:%d", nodeID, version)))
	}
	return tss.NewPartyID(partyID, label, key)
}

func partyIDToNodeID(partyID *tss.PartyID) string {
	if partyID == nil {
		return ""
	}
	nodeID, _, _ := strings.Cut(string(partyID.KeyInt().Bytes()), ":")
	return strings.TrimSpace(nodeID)
}

func partyIDsToNodeIDs(pids []*tss.PartyID) []string {
	out := make([]string, 0, len(pids))
	for _, p := range pids {
		out = append(out, partyIDToNodeID(p))
	}
	return out
}

func comparePartyIDs(x, y *tss.PartyID) bool {
	return bytes.Equal(x.KeyInt().Bytes(), y.KeyInt().Bytes())
}
