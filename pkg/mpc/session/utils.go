package session

import "github.com/bnb-chain/tss-lib/v2/tss"

// Moniker saves the routing partyID to nodeID mapping
func getRoutingFromPartyID(partyID *tss.PartyID) string {
	return partyID.Moniker
}
