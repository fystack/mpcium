package mpc

import (
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
)

type GetRoundFunc func(msg []byte, partyID *tss.PartyID, isBroadcast bool) (RoundInfo, error)

type RoundInfo struct {
	Index         int
	RoundMsg      string
	MsgIdentifier string
}

const (
	EDDSA_KEYGEN1            = "KGRound1Message"
	EDDSA_KEYGEN2aUnicast    = "KGRound2Message1"
	EDDSA_KEYGEN2b           = "KGRound2Message2"
	EDDSA_KEYSIGN1           = "SignRound1Message"
	EDDSA_KEYSIGN2           = "SignRound2Message"
	EDDSA_KEYSIGN3           = "SignRound3Message"
	EDDSA_RESHARING1         = "DGRound1Message"
	EDDSA_RESHARING2         = "DGRound2Message"
	EDDSA_RESHARING3aUnicast = "DGRound3Message1"
	EDDSA_RESHARING3bUnicast = "DGRound3Message2"
	EDDSA_RESHARING4         = "DGRound4Message"

	EDDSA_TSSKEYGENROUNDS  = 3
	EDDSA_TSSKEYSIGNROUNDS = 3
	EDDSA_RESHARINGROUNDS  = 4
)

func GetEddsaMsgRound(msg []byte, partyID *tss.PartyID, isBroadcast bool) (RoundInfo, error) {
	parsedMsg, err := tss.ParseWireMessage(msg, partyID, isBroadcast)
	if err != nil {
		return RoundInfo{}, err
	}
	switch parsedMsg.Content().(type) {
	case *keygen.KGRound1Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: EDDSA_KEYGEN1,
		}, nil

	case *keygen.KGRound2Message1:
		return RoundInfo{
			Index:    1,
			RoundMsg: EDDSA_KEYGEN2aUnicast,
		}, nil

	case *keygen.KGRound2Message2:
		return RoundInfo{
			Index:    2,
			RoundMsg: EDDSA_KEYGEN2b,
		}, nil

	case *signing.SignRound1Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: EDDSA_KEYSIGN1,
		}, nil

	case *signing.SignRound2Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: EDDSA_KEYSIGN2,
		}, nil

	case *signing.SignRound3Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: EDDSA_KEYSIGN3,
		}, nil

	case *resharing.DGRound1Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: EDDSA_RESHARING1,
		}, nil

	case *resharing.DGRound2Message:
		return RoundInfo{
			Index:    1,
			RoundMsg: EDDSA_RESHARING2,
		}, nil

	case *resharing.DGRound3Message1:
		return RoundInfo{
			Index:    2,
			RoundMsg: EDDSA_RESHARING3aUnicast,
		}, nil

	case *resharing.DGRound3Message2:
		return RoundInfo{
			Index:    3,
			RoundMsg: EDDSA_RESHARING3bUnicast,
		}, nil

	case *resharing.DGRound4Message:
		return RoundInfo{
			Index:    4,
			RoundMsg: EDDSA_RESHARING4,
		}, nil

	default:
		return RoundInfo{}, errors.New("unknown round")
	}
}
