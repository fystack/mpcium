package types

import (
	"encoding/binary"
	"errors"
)

// Route and To are not on the wire: the receiver takes them from the subject, and the signature covers both.
type DklsMessage struct {
	Route     string `json:"-"`
	To        string `json:"-"`
	From      string
	Phase     uint8
	Payload   []byte
	Signature []byte
}

const dklsWireVersion = 1

var errDklsWireTruncated = errors.New("dkls wire message truncated")

func (m *DklsMessage) MarshalForSigning() ([]byte, error) {
	buf := make([]byte, 0, 10+len(m.Route)+len(m.To)+len(m.From)+len(m.Payload))
	buf = appendBytes16(buf, []byte(m.Route))
	buf = appendBytes16(buf, []byte(m.To))
	buf = appendBytes16(buf, []byte(m.From))
	buf = append(buf, m.Phase)
	return append(buf, m.Payload...), nil
}

func (m *DklsMessage) MarshalWire() []byte {
	buf := make([]byte, 0, 8+len(m.From)+len(m.Payload)+len(m.Signature))
	buf = append(buf, dklsWireVersion, m.Phase)
	buf = appendBytes16(buf, []byte(m.From))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(m.Payload)))
	buf = append(buf, m.Payload...)
	return appendBytes16(buf, m.Signature)
}

func (m *DklsMessage) UnmarshalWire(data []byte) error {
	r := wireReader{data: data}
	if r.u8() != dklsWireVersion {
		return errors.New("unsupported dkls wire version")
	}
	m.Phase = r.u8()
	m.From = string(r.bytes16())
	m.Payload = r.bytes32()
	m.Signature = r.bytes16()
	return r.err
}

func appendBytes16(buf, b []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
	return append(buf, b...)
}

type wireReader struct {
	data []byte
	err  error
}

func (r *wireReader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.data) < n {
		r.err = errDklsWireTruncated
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

func (r *wireReader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *wireReader) bytes16() []byte {
	b := r.take(2)
	if b == nil {
		return nil
	}
	return r.take(int(binary.BigEndian.Uint16(b)))
}

func (r *wireReader) bytes32() []byte {
	b := r.take(4)
	if b == nil {
		return nil
	}
	return r.take(int(binary.BigEndian.Uint32(b)))
}
