package mpc

import (
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
)

const (
	KEYGEN1               = "KGRound1Message"
	KEYGEN2aUnicast       = "KGRound2Message1"
	KEYGEN2b              = "KGRound2Message2"
	KEYGEN3               = "KGRound3Message"
	KEYSIGN1aUnicast      = "SignRound1Message1"
	KEYSIGN1b             = "SignRound1Message2"
	KEYSIGN2Unicast       = "SignRound2Message"
	KEYSIGN3              = "SignRound3Message"
	KEYSIGN4              = "SignRound4Message"
	KEYSIGN5              = "SignRound5Message"
	KEYSIGN6              = "SignRound6Message"
	KEYSIGN7              = "SignRound7Message"
	KEYSIGN8              = "SignRound8Message"
	KEYSIGN9              = "SignRound9Message"
	KEYRESHARING1Unicast  = "DGRound1Message"
	KEYRESHARING2aUnicast = "DGRound2Message1"
	KEYRESHARING2bUnicast = "DGRound2Message2"
	KEYRESHARING3aUnicast = "DGRound3Message1"
	KEYRESHARING3b        = "DGRound3Message2"
	KEYRESHARING4a        = "DGRound4Message1"
	KEYRESHARING4bUnicast = "DGRound4Message2"

	TSSKEYGENROUNDS  = 4
	TSSKEYSIGNROUNDS = 10
)

func GetEcdsaMsgRound(msg []byte, partyID *tss.PartyID, isBroadcast bool) (RoundInfo, error) {
	parsedMsg, err := tss.ParseWireMessage(msg, partyID, isBroadcast)
	if err != nil {
		return RoundInfo{}, err
	}
	switch parsedMsg.Content().(type) {
	case *keygen.KGRound1Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: KEYGEN1,
		}, nil

	case *keygen.KGRound2Message1:
		return RoundInfo{
			Index:    1,
			RoundMsg: KEYGEN2aUnicast,
		}, nil

	case *keygen.KGRound2Message2:
		return RoundInfo{
			Index:    2,
			RoundMsg: KEYGEN2b,
		}, nil

	case *keygen.KGRound3Message:
		return RoundInfo{
			Index:    3,
			RoundMsg: KEYGEN3,
		}, nil

	case *signing.SignRound1Message1:
		return RoundInfo{
			Index:    0,
			RoundMsg: KEYSIGN1aUnicast,
		}, nil

	case *signing.SignRound1Message2:
		return RoundInfo{
			Index:    1,
			RoundMsg: KEYSIGN1b,
		}, nil

	case *signing.SignRound2Message:
		return RoundInfo{
			Index:    2,
			RoundMsg: KEYSIGN2Unicast,
		}, nil

	case *signing.SignRound3Message:
		return RoundInfo{
			Index:    3,
			RoundMsg: KEYSIGN3,
		}, nil

	case *signing.SignRound4Message:
		return RoundInfo{
			Index:    4,
			RoundMsg: KEYSIGN4,
		}, nil

	case *signing.SignRound5Message:
		return RoundInfo{
			Index:    5,
			RoundMsg: KEYSIGN5,
		}, nil

	case *signing.SignRound6Message:
		return RoundInfo{
			Index:    6,
			RoundMsg: KEYSIGN6,
		}, nil

	case *signing.SignRound7Message:
		return RoundInfo{
			Index:    7,
			RoundMsg: KEYSIGN7,
		}, nil
	case *signing.SignRound8Message:
		return RoundInfo{
			Index:    8,
			RoundMsg: KEYSIGN8,
		}, nil
	case *signing.SignRound9Message:
		return RoundInfo{
			Index:    9,
			RoundMsg: KEYSIGN9,
		}, nil
	case *resharing.DGRound1Message:
		return RoundInfo{
			Index:    0,
			RoundMsg: KEYRESHARING1Unicast,
		}, nil
	case *resharing.DGRound2Message1:
		return RoundInfo{
			Index:    1,
			RoundMsg: KEYRESHARING2aUnicast,
		}, nil
	case *resharing.DGRound2Message2:
		return RoundInfo{
			Index:    2,
			RoundMsg: KEYRESHARING2bUnicast,
		}, nil
	case *resharing.DGRound3Message1:
		return RoundInfo{
			Index:    3,
			RoundMsg: KEYRESHARING3aUnicast,
		}, nil
	case *resharing.DGRound3Message2:
		return RoundInfo{
			Index:    4,
			RoundMsg: KEYRESHARING3b,
		}, nil
	case *resharing.DGRound4Message1:
		return RoundInfo{
			Index:    5,
			RoundMsg: KEYRESHARING4a,
		}, nil
	case *resharing.DGRound4Message2:
		return RoundInfo{
			Index:    6,
			RoundMsg: KEYRESHARING4bUnicast,
		}, nil
	default:
		return RoundInfo{}, errors.New("unknown round")
	}
}
