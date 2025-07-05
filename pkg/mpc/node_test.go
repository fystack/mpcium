package mpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPartyIDToNodeID(t *testing.T) {
	partyID := createPartyID("4d8cb873-dc86-4776-b6f6-cf5c668f6468", "keygen", 1)
	nodeID := PartyIDToRoutingDest(partyID)
	assert.Equal(t, nodeID, "4d8cb873-dc86-4776-b6f6-cf5c668f6468:1", "NodeID should be equal")
}

func TestCreatePartyID_Structure(t *testing.T) {
	sessionID := "test-session-123"
	keyType := "keygen"
	version := 5

	partyID := createPartyID(sessionID, keyType, version)

	assert.NotNil(t, partyID)
	// The party ID has a random UUID as the ID
	assert.NotEmpty(t, partyID.Id)
	// The Moniker should contain the keyType
	assert.Equal(t, keyType, partyID.Moniker)
	// The Key should be derived from sessionID and version
	assert.NotNil(t, partyID.Key)
}

func TestCreatePartyID_DifferentVersions(t *testing.T) {
	sessionID := "test-session-456"
	keyType := "keygen"

	// Test version 0 (backward compatible)
	partyID0 := createPartyID(sessionID, keyType, BackwardCompatibleVersion)
	assert.NotNil(t, partyID0)
	assert.Equal(t, keyType, partyID0.Moniker)

	// Test version 1 (default)
	partyID1 := createPartyID(sessionID, keyType, DefaultVersion)
	assert.NotNil(t, partyID1)
	assert.Equal(t, keyType, partyID1.Moniker)

	// Different versions should have different keys
	assert.NotEqual(t, partyID0.Key, partyID1.Key)
}

func TestPartyIDToRoutingDest_BackwardCompatible(t *testing.T) {
	sessionID := "test-session-789"
	keyType := "signing"

	partyID := createPartyID(sessionID, keyType, BackwardCompatibleVersion)
	nodeID := PartyIDToRoutingDest(partyID)

	// For backward compatible version, should just be the sessionID
	assert.Equal(t, sessionID, nodeID)
}

func TestPartyIDToRoutingDest_DefaultVersion(t *testing.T) {
	sessionID := "test-session-999"
	keyType := "signing"

	partyID := createPartyID(sessionID, keyType, DefaultVersion)
	nodeID := PartyIDToRoutingDest(partyID)

	// For default version, should include the version number
	expected := sessionID + ":1"
	assert.Equal(t, expected, nodeID)
}

func TestCreatePartyID_EmptyValues(t *testing.T) {
	// Test with empty session ID
	partyID := createPartyID("", "keygen", 0)
	assert.NotNil(t, partyID)
	assert.Equal(t, "keygen", partyID.Moniker)

	// Test with empty key type
	partyID = createPartyID("session", "", 1)
	assert.NotNil(t, partyID)
	assert.Equal(t, "", partyID.Moniker)
}

func TestPartyIDToRoutingDest_Consistency(t *testing.T) {
	sessionID := "consistent-session"
	keyType := "keygen"
	version := 3

	// Create the same party ID multiple times
	partyID1 := createPartyID(sessionID, keyType, version)
	partyID2 := createPartyID(sessionID, keyType, version)

	nodeID1 := PartyIDToRoutingDest(partyID1)
	nodeID2 := PartyIDToRoutingDest(partyID2)

	// Should produce consistent results based on sessionID and version
	assert.Equal(t, nodeID1, nodeID2, "Same parameters should produce same routing destinations")
}

func TestCreatePartyID_UniqueIDs(t *testing.T) {
	sessionID := "test-session"
	keyType := "keygen"
	version := 1

	// Create multiple party IDs with same parameters
	partyID1 := createPartyID(sessionID, keyType, version)
	partyID2 := createPartyID(sessionID, keyType, version)

	// IDs should be different (random UUIDs)
	assert.NotEqual(t, partyID1.Id, partyID2.Id, "Party IDs should have unique random IDs")

	// But monikers should be the same
	assert.Equal(t, partyID1.Moniker, partyID2.Moniker)

	// And keys should be the same (derived from sessionID and version)
	assert.Equal(t, partyID1.Key, partyID2.Key)
}
