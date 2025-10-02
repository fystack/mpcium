package taurus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPartyIDToNodeID(t *testing.T) {
	partyID := createPartyID("4d8cb873-dc86-4776-b6f6-cf5c668f6468", "keygen", 1)
	nodeID := PartyIDToRoutingDest(partyID)
	assert.Equal(t, "4d8cb873-dc86-4776-b6f6-cf5c668f6468:keygen:1", nodeID, "NodeID should be equal")
}

func TestCreatePartyID_Structure(t *testing.T) {
	sessionID := "test-session-123"
	keyType := "keygen"
	version := 5

	partyID := createPartyID(sessionID, keyType, version)

	assert.NotNil(t, partyID)
	// The party ID should be in the format sessionID:keyType:version
	expectedID := "test-session-123:keygen:5"
	assert.Equal(t, expectedID, string(partyID))
}

func TestCreatePartyID_DifferentVersions(t *testing.T) {
	sessionID := "test-session-456"
	keyType := "keygen"

	// Test version 0 (backward compatible)
	partyID0 := createPartyID(sessionID, keyType, 0)
	assert.NotNil(t, partyID0)
	// Version 0 should just be the sessionID
	assert.Equal(t, sessionID, string(partyID0))

	// Test version 1 (default)
	partyID1 := createPartyID(sessionID, keyType, DefaultVersion)
	assert.NotNil(t, partyID1)
	// Version 1 should include version info
	expectedID1 := "test-session-456:keygen:1"
	assert.Equal(t, expectedID1, string(partyID1))

	// Different versions should produce different party IDs
	assert.NotEqual(t, partyID0, partyID1)
}

func TestPartyIDToRoutingDest_BackwardCompatible(t *testing.T) {
	sessionID := "test-session-789"
	keyType := "signing"

	partyID := createPartyID(sessionID, keyType, 0)
	nodeID := PartyIDToRoutingDest(partyID)

	// For backward compatible version, should just be the sessionID
	assert.Equal(t, sessionID, nodeID)
}

func TestPartyIDToRoutingDest_DefaultVersion(t *testing.T) {
	sessionID := "test-session-999"
	keyType := "signing"

	partyID := createPartyID(sessionID, keyType, DefaultVersion)
	nodeID := PartyIDToRoutingDest(partyID)

	// For default version, should be the full party ID string
	expected := "test-session-999:signing:1"
	assert.Equal(t, expected, nodeID)
}

func TestCreatePartyID_EmptyValues(t *testing.T) {
	// Test with empty session ID
	partyID := createPartyID("", "keygen", 0)
	assert.NotNil(t, partyID)
	// Version 0 should just return empty string
	assert.Equal(t, "", string(partyID))

	// Test with empty key type
	partyID = createPartyID("session", "", 1)
	assert.NotNil(t, partyID)
	// Should still create the party ID with format
	expectedID := "session::1"
	assert.Equal(t, expectedID, string(partyID))
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

func TestCreatePartyID_SameParameters(t *testing.T) {
	sessionID := "test-session"
	keyType := "keygen"
	version := 1

	// Create multiple party IDs with same parameters
	partyID1 := createPartyID(sessionID, keyType, version)
	partyID2 := createPartyID(sessionID, keyType, version)

	// Party IDs with same parameters should be identical in the new implementation
	assert.Equal(t, partyID1, partyID2, "Party IDs with same parameters should be equal")

	// Both should have the same format
	expectedID := "test-session:keygen:1"
	assert.Equal(t, expectedID, string(partyID1))
	assert.Equal(t, expectedID, string(partyID2))
}
