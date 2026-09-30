//go:build dklsbench

package dklsvstss

import (
	"errors"

	"github.com/fystack/DKLs23/wrapper/go-ll/dkls"
)

// runDklsDKG runs an in-process DKLs23 DKG for n parties, threshold t (t-of-n signers required).
func runDklsDKG(n, t uint8) ([]*dkls.Party, error) {
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i)
	}

	sessions := make([]*dkls.DkgSession, n)
	for i := uint8(0); i < n; i++ {
		var err error
		sessions[i], err = dkls.NewDkgSession(t, n, i+1, sessionID)
		if err != nil {
			return nil, err
		}
		defer sessions[i].Free()
	}

	msg1 := make([][]dkls.Message, n)
	for i, s := range sessions {
		var err error
		msg1[i], err = s.Phase1()
		if err != nil {
			return nil, err
		}
	}

	msg2 := make([][]dkls.Message, n)
	for i, s := range sessions {
		incoming := make([]dkls.Message, 0)
		for _, msgs := range msg1 {
			for _, m := range msgs {
				if m.Kind == dkls.MsgPolyFragment && m.ToID == uint8(i+1) {
					incoming = append(incoming, m)
				}
			}
		}
		var err error
		msg2[i], err = s.Phase2(incoming)
		if err != nil {
			return nil, err
		}
	}

	msg3 := make([][]dkls.Message, n)
	for i, s := range sessions {
		var err error
		msg3[i], err = s.Phase3()
		if err != nil {
			return nil, err
		}
	}

	shares := make([]*dkls.Party, n)
	for i, s := range sessions {
		incoming := make([]dkls.Message, 0)
		for _, msgs := range msg3 {
			for _, m := range msgs {
				if m.ToID == uint8(i+1) || m.ToID == 255 {
					incoming = append(incoming, m)
				}
			}
		}
		for _, msgs := range msg2 {
			for _, m := range msgs {
				if m.Kind == dkls.MsgDkgZeroP2 && m.ToID == uint8(i+1) {
					incoming = append(incoming, m)
				}
			}
		}
		for _, msgs := range msg2 {
			for _, m := range msgs {
				if m.ToID == 255 {
					incoming = append(incoming, m)
				}
			}
		}
		var err error
		shares[i], err = s.Phase4(incoming)
		if err != nil {
			return nil, err
		}
	}

	return shares, nil
}

// runDklsSign runs an in-process DKLs23 threshold signature over exactly t signers.
func runDklsSign(signers []*dkls.Party, messageHash []byte) ([][]byte, error) {
	n := len(signers)
	if n == 0 {
		return nil, errors.New("no signers")
	}
	t := int(signers[0].Threshold())
	if n != t {
		return nil, errors.New("runDklsSign requires exactly threshold signers")
	}

	signerIDs := make([]uint8, n)
	for i := 0; i < n; i++ {
		signerIDs[i] = signers[i].PartyID()
	}

	sessions := make([]*dkls.SignSession, n)
	signID := make([]byte, 32)
	for i := 0; i < n; i++ {
		counterparties := make([]uint8, 0, n-1)
		for _, id := range signerIDs {
			if id != signers[i].PartyID() {
				counterparties = append(counterparties, id)
			}
		}
		var err error
		sessions[i], err = dkls.NewSignSession(signers[i], signID, counterparties, messageHash)
		if err != nil {
			return nil, err
		}
		defer sessions[i].Free()
	}

	msg1 := make([][]dkls.Message, n)
	for i, s := range sessions {
		out, err := s.Phase1()
		if err != nil {
			return nil, err
		}
		msg1[i] = out
	}

	msg2 := make([][]dkls.Message, n)
	for i, s := range sessions {
		in := collect(msg1, signers[i].PartyID(), dkls.MsgSignPhase1)
		out, err := s.Phase2(in)
		if err != nil {
			return nil, err
		}
		msg2[i] = out
	}

	msg3 := make([][]dkls.Message, n)
	for i, s := range sessions {
		in := collect(msg2, signers[i].PartyID(), dkls.MsgSignPhase2)
		out, err := s.Phase3(in)
		if err != nil {
			return nil, err
		}
		msg3[i] = out
	}

	in := collectBroadcast(msg3, dkls.MsgSignBroadcast)
	signatures := make([][]byte, t)
	for i := 0; i < t; i++ {
		sig, err := sessions[i].Phase4(in, true)
		if err != nil {
			return nil, err
		}
		signatures[i] = sig
	}

	return signatures, nil
}

func collect(all [][]dkls.Message, receiver uint8, kind dkls.MessageKind) []dkls.Message {
	out := make([]dkls.Message, 0)
	for _, batch := range all {
		for _, msg := range batch {
			if msg.Kind == kind && msg.ToID == receiver {
				out = append(out, msg)
			}
		}
	}
	return out
}

func collectBroadcast(all [][]dkls.Message, kind dkls.MessageKind) []dkls.Message {
	out := make([]dkls.Message, 0)
	for _, batch := range all {
		for _, msg := range batch {
			if msg.Kind == kind && msg.ToID == 255 {
				out = append(out, msg)
			}
		}
	}
	return out
}
