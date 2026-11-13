package amqpfake

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	frameMethod    = 1
	frameHeader    = 2
	frameBody      = 3
	frameHeartbeat = 8
	frameEnd       = 0xCE
)

var protocolHeader = []byte("AMQP\x00\x00\x09\x01")

type frame struct {
	typ     byte
	channel uint16
	payload []byte
}

func readFrame(r *bufio.Reader, max uint32) (frame, error) {
	var hdr [7]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[3:])
	if max > 0 && size > max {
		return frame{}, fmt.Errorf("frame of %d bytes exceeds frame-max %d", size, max)
	}
	payload := make([]byte, size+1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame{}, err
	}
	if payload[size] != frameEnd {
		return frame{}, errors.New("missing frame-end octet")
	}
	return frame{typ: hdr[0], channel: binary.BigEndian.Uint16(hdr[1:3]), payload: payload[:size]}, nil
}

func encodeFrame(typ byte, channel uint16, payload []byte) []byte {
	b := make([]byte, 7, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[1:3], channel)
	binary.BigEndian.PutUint32(b[3:7], uint32(len(payload)))
	b = append(b, payload...)
	return append(b, frameEnd)
}

// args decodes method arguments.
type args struct {
	b   []byte
	err error
}

func (a *args) take(n int) []byte {
	if a.err != nil {
		return make([]byte, n)
	}
	if len(a.b) < n {
		a.err = io.ErrUnexpectedEOF
		return make([]byte, n)
	}
	v := a.b[:n]
	a.b = a.b[n:]
	return v
}

func (a *args) octet() byte             { return a.take(1)[0] }
func (a *args) short() uint16           { return binary.BigEndian.Uint16(a.take(2)) }
func (a *args) long() uint32            { return binary.BigEndian.Uint32(a.take(4)) }
func (a *args) longlong() uint64        { return binary.BigEndian.Uint64(a.take(8)) }
func (a *args) shortstr() string        { return string(a.take(int(a.octet()))) }
func (a *args) longstr() []byte         { return a.take(int(a.long())) }
func (a *args) table() []byte           { return a.longstr() }
func (a *args) bit(b byte, n uint) bool { return b&(1<<n) != 0 }

// enc encodes method arguments.
type enc struct{ b []byte }

func method(class, id uint16) *enc {
	e := &enc{}
	return e.short(class).short(id)
}

func (e *enc) octet(v byte) *enc { e.b = append(e.b, v); return e }
func (e *enc) short(v uint16) *enc {
	e.b = binary.BigEndian.AppendUint16(e.b, v)
	return e
}
func (e *enc) long(v uint32) *enc {
	e.b = binary.BigEndian.AppendUint32(e.b, v)
	return e
}
func (e *enc) longlong(v uint64) *enc {
	e.b = binary.BigEndian.AppendUint64(e.b, v)
	return e
}
func (e *enc) shortstr(s string) *enc {
	if len(s) > 255 {
		s = s[:255]
	}
	e.b = append(e.b, byte(len(s)))
	e.b = append(e.b, s...)
	return e
}
func (e *enc) longstr(s []byte) *enc {
	e.long(uint32(len(s)))
	e.b = append(e.b, s...)
	return e
}

// table encodes a flat table of string / long-string values.
func (e *enc) table(kv map[string]any) *enc {
	t := &enc{}
	for k, v := range kv {
		t.shortstr(k)
		switch x := v.(type) {
		case string:
			t.octet('S').longstr([]byte(x))
		case bool:
			t.octet('t')
			if x {
				t.octet(1)
			} else {
				t.octet(0)
			}
		case map[string]any:
			t.octet('F').table(x)
		}
	}
	return e.longstr(t.b)
}
