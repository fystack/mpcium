//go:build dklsbench

package dklsvstss

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

func genTestPartyIDs(n int) tss.SortedPartyIDs {
	ids := make(tss.UnSortedPartyIDs, n)
	for i := 0; i < n; i++ {
		ids[i] = tss.NewPartyID(string(rune('1'+i)), "peer", big.NewInt(int64(i+1)))
	}
	return tss.SortPartyIDs(ids)
}

// runTssKeygen runs an in-process tss-lib ECDSA keygen for n parties with the given threshold
// (threshold+1 parties are required to sign). preParams must be pre-generated per party.
func runTssKeygen(n, threshold int, preParams []*keygen.LocalPreParams) ([]*keygen.LocalPartySaveData, error) {
	partyIDs := genTestPartyIDs(n)
	ctx := tss.NewPeerContext(partyIDs)

	// Buffer generously: a small buffer can leave a trailing goroutine (spawned by
	// routeTssMessage for a message produced after the round we're waiting on already
	// completed) blocked on a send forever once this function returns and stops
	// draining outCh. Those leaked, permanently-blocked goroutines then starve any
	// process-global concurrency-limited resource tss-lib uses (e.g. its proof
	// verification worker pool), hanging unrelated *later* keygen/sign calls in the
	// same process even though this call itself finished successfully.
	outCh := make(chan tss.Message, 256)
	endCh := make(chan *keygen.LocalPartySaveData, n)
	errCh := make(chan *tss.Error, n)

	parties := make([]tss.Party, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), ctx, partyIDs[i], n, threshold)
		parties[i] = keygen.NewLocalParty(params, outCh, endCh, *preParams[i])
	}

	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}

	results := make([]*keygen.LocalPartySaveData, 0, n)
	for len(results) < n {
		select {
		case err := <-errCh:
			return nil, err
		case msg := <-outCh:
			if err := routeTssMessage(parties, msg); err != nil {
				return nil, err
			}
		case save := <-endCh:
			results = append(results, save)
		}
	}
	return results, nil
}

// runTssSign runs an in-process tss-lib ECDSA signing round over all n key holders
// (n-of-n: the signer set must be exactly the parties that ran keygen together, same
// PartyID objects, to avoid tss-lib's LocalPartySaveData subset-remap edge cases).
func runTssSign(keys []*keygen.LocalPartySaveData, partyIDs tss.SortedPartyIDs, threshold int, msgHash *big.Int) ([]*common.SignatureData, error) {
	n := len(keys)
	ctx := tss.NewPeerContext(partyIDs)

	outCh := make(chan tss.Message, 256)
	endCh := make(chan *common.SignatureData, n)
	errCh := make(chan *tss.Error, n)

	parties := make([]tss.Party, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), ctx, partyIDs[i], n, threshold)
		parties[i] = signing.NewLocalParty(msgHash, params, *keys[i], outCh, endCh)
	}

	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}

	results := make([]*common.SignatureData, 0, n)
	for len(results) < n {
		select {
		case err := <-errCh:
			return nil, err
		case msg := <-outCh:
			if err := routeTssMessage(parties, msg); err != nil {
				return nil, err
			}
		case sig := <-endCh:
			results = append(results, sig)
		}
	}
	return results, nil
}

func routeTssMessage(parties []tss.Party, msg tss.Message) error {
	dest := msg.GetTo()
	if dest == nil {
		for _, p := range parties {
			if p.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go updateParty(p, msg)
		}
		return nil
	}
	for _, to := range dest {
		found := false
		for _, p := range parties {
			if p.PartyID().Index == to.Index {
				found = true
				go updateParty(p, msg)
				break
			}
		}
		if !found {
			return errors.New("destination party not found")
		}
	}
	return nil
}

func updateParty(p tss.Party, msg tss.Message) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		return
	}
	_, _ = p.UpdateFromBytes(bz, msg.GetFrom(), msg.IsBroadcast())
}
