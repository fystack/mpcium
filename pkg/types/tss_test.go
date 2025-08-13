package types

import (
	"testing"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTssMessage(t *testing.T) {
	walletID := "test-wallet-123"
	msgBytes := []byte("test message")
	isBroadcast := true
	from := &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      "party1",
			Moniker: "moniker1",
		},
		Index: 0,
	}
	to := []*tss.PartyID{
		{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      "party2",
				Moniker: "moniker2",
			},
			Index: 1,
		},
	}

	tssMsg := NewTssMessage(walletID, msgBytes, isBroadcast, from, to)

	assert.Equal(t, walletID, tssMsg.WalletID)
	assert.Equal(t, msgBytes, tssMsg.MsgBytes)
	assert.Equal(t, isBroadcast, tssMsg.IsBroadcast)
	assert.Equal(t, from, tssMsg.From)
	assert.Equal(t, to, tssMsg.To)
	assert.False(t, tssMsg.IsToOldCommittee)
	assert.False(t, tssMsg.IsToOldAndNewCommittees)
	assert.Nil(t, tssMsg.Signature)
}

func TestMarshalUnmarshalTssMessage(t *testing.T) {
	from := &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      "party1",
			Moniker: "moniker1",
		},
		Index: 0,
	}
	to := []*tss.PartyID{
		{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      "party2",
				Moniker: "moniker2",
			},
			Index: 1,
		},
	}

	originalMsg := NewTssMessage("wallet-123", []byte("test data"), true, from, to)
	originalMsg.Signature = []byte("test-signature")

	// Test marshaling
	msgBytes, err := MarshalTssMessage(&originalMsg)
	require.NoError(t, err)
	assert.NotEmpty(t, msgBytes)

	// Test unmarshaling
	unmarshaled, err := UnmarshalTssMessage(msgBytes)
	require.NoError(t, err)
	assert.Equal(t, originalMsg.WalletID, unmarshaled.WalletID)
	assert.Equal(t, originalMsg.MsgBytes, unmarshaled.MsgBytes)
	assert.Equal(t, originalMsg.IsBroadcast, unmarshaled.IsBroadcast)
	assert.Equal(t, originalMsg.Signature, unmarshaled.Signature)
}

func TestMarshalTssResharingMessage(t *testing.T) {
	msgBytes := []byte("resharing message")
	isToOldCommittee := true
	isBroadcast := false
	isToOldAndNewCommittees := true
	from := &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      "party1",
			Moniker: "moniker1",
		},
		Index: 0,
	}
	to := []*tss.PartyID{
		{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      "party2",
				Moniker: "moniker2",
			},
			Index: 1,
		},
	}

	result, err := MarshalTssResharingMessage(msgBytes, isToOldCommittee, isBroadcast, isToOldAndNewCommittees, from, to)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Unmarshal to verify structure
	unmarshaled, err := UnmarshalTssMessage(result)
	require.NoError(t, err)
	assert.Equal(t, msgBytes, unmarshaled.MsgBytes)
	assert.Equal(t, isToOldCommittee, unmarshaled.IsToOldCommittee)
	assert.Equal(t, isBroadcast, unmarshaled.IsBroadcast)
	assert.Equal(t, isToOldAndNewCommittees, unmarshaled.IsToOldAndNewCommittees)
}

func TestMarshalUnmarshalStartMessage(t *testing.T) {
	params := []byte("start parameters")

	// Test marshaling
	msgBytes, err := MarshalStartMessage(params)
	require.NoError(t, err)
	assert.NotEmpty(t, msgBytes)

	// Test unmarshaling
	unmarshaled, err := UnmarshalStartMessage(msgBytes)
	require.NoError(t, err)
	assert.Equal(t, params, unmarshaled.Params)
}

func TestMarshalForSigning(t *testing.T) {
	from := &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      "party1",
			Moniker: "moniker1",
		},
		Index: 0,
	}
	to := []*tss.PartyID{
		{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      "party2",
				Moniker: "moniker2",
			},
			Index: 1,
		},
	}

	msg := NewTssMessage("wallet-123", []byte("test data"), true, from, to)
	msg.IsToOldCommittee = true
	msg.IsToOldAndNewCommittees = false

	signingBytes, err := msg.MarshalForSigning()
	require.NoError(t, err)
	assert.NotEmpty(t, signingBytes)

	// Test deterministic output - same message should produce same bytes
	signingBytes2, err := msg.MarshalForSigning()
	require.NoError(t, err)
	assert.Equal(t, signingBytes, signingBytes2)
}

func TestUnmarshalTssMessage_InvalidJSON(t *testing.T) {
	invalidJSON := []byte("invalid json")

	_, err := UnmarshalTssMessage(invalidJSON)
	assert.Error(t, err)
}

func TestUnmarshalStartMessage_InvalidJSON(t *testing.T) {
	invalidJSON := []byte("invalid json")

	_, err := UnmarshalStartMessage(invalidJSON)
	assert.Error(t, err)
}
