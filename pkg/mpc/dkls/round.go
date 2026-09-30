//go:build dkls

package dkls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	dklsll "github.com/fystack/DKLs23/wrapper/go-ll/dkls"
	"github.com/fystack/mpcium/pkg/types"
)

const phaseTimeout = 60 * time.Second

type Phase uint8

const (
	PhaseKG1 Phase = iota + 1
	PhaseKG2
	PhaseKG3
	PhaseSG1
	PhaseSG2
	PhaseSG3
)

// Point-to-point payloads are encrypted for their recipient; broadcast entries stay public.
type MessageCipher interface {
	EncryptMessage(plaintext []byte, peerID string) ([]byte, error)
	DecryptMessage(cipher []byte, peerID string) ([]byte, error)
}

type receivedBundle struct {
	from    string
	payload []byte
}

type round struct {
	selfNodeID string
	self       uint8
	partyIDs   map[string]uint8
	transport  Transport
	cipher     MessageCipher
	timeout    time.Duration
	early      map[Phase][]receivedBundle
}

func newRound(selfNodeID string, self uint8, partyIDs map[string]uint8, transport Transport, cipher MessageCipher) *round {
	return &round{
		selfNodeID: selfNodeID,
		self:       self,
		partyIDs:   partyIDs,
		transport:  transport,
		cipher:     cipher,
		timeout:    phaseTimeout,
		early:      make(map[Phase][]receivedBundle),
	}
}

func (r *round) exchange(phase Phase, out []dklsll.Message, peers []string) ([]dklsll.Message, error) {
	if err := r.send(phase, out, peers); err != nil {
		return nil, err
	}
	received, err := r.receive(phase, peers)
	if err != nil {
		return nil, err
	}
	all := make([]dklsll.Message, 0, len(out)+len(received))
	all = append(all, out...)
	return append(all, received...), nil
}

func (r *round) send(phase Phase, msgs []dklsll.Message, peers []string) error {
	for _, peer := range peers {
		peerParty := r.partyIDs[peer]
		entries := make([]dklsll.Message, 0, len(msgs))
		for _, m := range msgs {
			switch m.ToID {
			case broadcastToID:
				entries = append(entries, m)
			case peerParty:
				ciphertext, err := r.cipher.EncryptMessage(m.Payload, peer)
				if err != nil {
					return fmt.Errorf("encrypt dkls payload for %s: %w", peer, err)
				}
				m.Payload = ciphertext
				entries = append(entries, m)
			}
		}
		msg := types.DklsMessage{From: r.selfNodeID, Phase: uint8(phase), Payload: encodeBundle(entries)}
		if err := r.transport.Send(peer, msg); err != nil {
			return err
		}
	}
	return nil
}

func (r *round) receive(phase Phase, peers []string) ([]dklsll.Message, error) {
	expected := make(map[string]bool, len(peers))
	for _, peer := range peers {
		expected[peer] = true
	}

	var all []dklsll.Message
	accept := func(b receivedBundle) error {
		if !expected[b.from] {
			return nil
		}
		delete(expected, b.from)
		msgs, err := r.open(b)
		if err != nil {
			return err
		}
		all = append(all, msgs...)
		return nil
	}

	for _, b := range r.early[phase] {
		if err := accept(b); err != nil {
			return nil, err
		}
	}
	delete(r.early, phase)

	timeout := time.NewTimer(r.timeout)
	defer timeout.Stop()
	for len(expected) > 0 {
		select {
		case msg, ok := <-r.transport.Inbox():
			if !ok {
				return nil, errors.New("dkls transport closed while waiting for messages")
			}
			b := receivedBundle{from: msg.From, payload: msg.Payload}
			if Phase(msg.Phase) != phase {
				r.early[Phase(msg.Phase)] = append(r.early[Phase(msg.Phase)], b)
				continue
			}
			if err := accept(b); err != nil {
				return nil, err
			}
		case <-timeout.C:
			return nil, fmt.Errorf("timeout waiting for dkls phase %d: %d of %d peers missing", phase, len(expected), len(peers))
		}
	}
	return all, nil
}

func (r *round) open(b receivedBundle) ([]dklsll.Message, error) {
	msgs, err := decodeBundle(b.payload)
	if err != nil {
		return nil, fmt.Errorf("decode dkls bundle from %s: %w", b.from, err)
	}
	for i, m := range msgs {
		if m.ToID != r.self {
			continue
		}
		plaintext, err := r.cipher.DecryptMessage(m.Payload, b.from)
		if err != nil {
			return nil, fmt.Errorf("decrypt dkls payload from %s: %w", b.from, err)
		}
		msgs[i].Payload = plaintext
	}
	return msgs, nil
}

const broadcastToID = 255

var errBundleTruncated = errors.New("dkls bundle truncated")

func encodeBundle(entries []dklsll.Message) []byte {
	size := 2
	for _, m := range entries {
		size += 7 + len(m.Payload)
	}
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(entries)))
	for _, m := range entries {
		buf = append(buf, m.FromID, m.ToID, byte(m.Kind))
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(m.Payload)))
		buf = append(buf, m.Payload...)
	}
	return buf
}

func decodeBundle(data []byte) ([]dklsll.Message, error) {
	if len(data) < 2 {
		return nil, errBundleTruncated
	}
	count := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	msgs := make([]dklsll.Message, 0, count)
	for range count {
		if len(data) < 7 {
			return nil, errBundleTruncated
		}
		n := int(binary.BigEndian.Uint32(data[3:7]))
		if len(data) < 7+n {
			return nil, errBundleTruncated
		}
		msgs = append(msgs, dklsll.Message{
			FromID:  data[0],
			ToID:    data[1],
			Kind:    dklsll.MessageKind(data[2]),
			Payload: data[7 : 7+n],
		})
		data = data[7+n:]
	}
	return msgs, nil
}

func selectMessages(msgs []dklsll.Message, keep func(dklsll.Message) bool) []dklsll.Message {
	out := make([]dklsll.Message, 0, len(msgs))
	for _, m := range msgs {
		if keep(m) {
			out = append(out, m)
		}
	}
	return out
}

func addressedTo(msgs []dklsll.Message, self uint8) []dklsll.Message {
	return selectMessages(msgs, func(m dklsll.Message) bool { return m.ToID == self || m.ToID == broadcastToID })
}

func ofKind(msgs []dklsll.Message, kind dklsll.MessageKind, to uint8) []dklsll.Message {
	return selectMessages(msgs, func(m dklsll.Message) bool { return m.Kind == kind && m.ToID == to })
}

func broadcasts(msgs []dklsll.Message) []dklsll.Message {
	return selectMessages(msgs, func(m dklsll.Message) bool { return m.ToID == broadcastToID })
}

func broadcastsOfKind(msgs []dklsll.Message, kind dklsll.MessageKind) []dklsll.Message {
	return selectMessages(msgs, func(m dklsll.Message) bool { return m.Kind == kind && m.ToID == broadcastToID })
}
