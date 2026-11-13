// Package sio is a hand-rolled Engine.IO v4 + Socket.IO v5 client.
//
// The Engine.IO layer (engine.go) speaks the websocket and long-polling
// transports (with polling-to-websocket upgrade); the Socket.IO layer
// (client.go) multiplexes namespaces over one Engine.IO connection and
// handles events, acknowledgements and binary attachments.
package sio

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Engine.IO v4 packet types.
const (
	EOpen    byte = '0'
	EClose   byte = '1'
	EPing    byte = '2'
	EPong    byte = '3'
	EMessage byte = '4'
	EUpgrade byte = '5'
	ENoop    byte = '6'
)

// RecordSeparator separates packets in a long-polling payload.
const RecordSeparator = '\x1e'

// EPacket is one Engine.IO packet. Binary packets are always messages and
// carry raw bytes in Data.
type EPacket struct {
	Type   byte
	Data   []byte
	Binary bool
}

// TextPacket builds a text Engine.IO packet.
func TextPacket(t byte, data string) EPacket { return EPacket{Type: t, Data: []byte(data)} }

// BinaryPacket builds a binary Engine.IO message packet.
func BinaryPacket(data []byte) EPacket { return EPacket{Type: EMessage, Data: data, Binary: true} }

// WSFrame returns the websocket representation of p: binary packets are sent
// as raw binary frames, text packets as "<type><data>" text frames.
func (p EPacket) WSFrame() (binary bool, payload []byte) {
	if p.Binary {
		return true, p.Data
	}
	out := make([]byte, 0, len(p.Data)+1)
	out = append(out, p.Type)
	return false, append(out, p.Data...)
}

// DecodeWSFrame parses one websocket frame into a packet.
func DecodeWSFrame(binary bool, b []byte) (EPacket, error) {
	if binary {
		return BinaryPacket(b), nil
	}
	if len(b) == 0 {
		return EPacket{}, errors.New("engine.io: empty packet")
	}
	if b[0] < EOpen || b[0] > ENoop {
		return EPacket{}, fmt.Errorf("engine.io: unknown packet type %q", b[0])
	}
	return EPacket{Type: b[0], Data: b[1:]}, nil
}

// EncodePolling encodes packets as a long-polling payload: packets are
// separated by \x1e and binary packets are encoded as "b<base64>".
func EncodePolling(pkts []EPacket) []byte {
	var buf bytes.Buffer
	for i, p := range pkts {
		if i > 0 {
			buf.WriteByte(RecordSeparator)
		}
		if p.Binary {
			buf.WriteByte('b')
			buf.WriteString(base64.StdEncoding.EncodeToString(p.Data))
			continue
		}
		buf.WriteByte(p.Type)
		buf.Write(p.Data)
	}
	return buf.Bytes()
}

// DecodePolling parses a long-polling payload.
func DecodePolling(b []byte) ([]EPacket, error) {
	if len(b) == 0 {
		return nil, errors.New("engine.io: empty polling payload")
	}
	var out []EPacket
	for _, rec := range bytes.Split(b, []byte{RecordSeparator}) {
		if len(rec) == 0 {
			return nil, errors.New("engine.io: empty packet in polling payload")
		}
		if rec[0] == 'b' {
			data, err := base64.StdEncoding.DecodeString(string(rec[1:]))
			if err != nil {
				return nil, fmt.Errorf("engine.io: bad base64 binary packet: %w", err)
			}
			out = append(out, BinaryPacket(data))
			continue
		}
		p, err := DecodeWSFrame(false, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Handshake is the Engine.IO open packet payload.
type Handshake struct {
	SID          string   `json:"sid"`
	Upgrades     []string `json:"upgrades"`
	PingInterval int      `json:"pingInterval"`
	PingTimeout  int      `json:"pingTimeout"`
	MaxPayload   int64    `json:"maxPayload"`
}

// ParseHandshake parses an open packet.
func ParseHandshake(p EPacket) (*Handshake, error) {
	if p.Binary || p.Type != EOpen {
		return nil, fmt.Errorf("engine.io: expected open packet, got type %q", p.Type)
	}
	var h Handshake
	if err := json.Unmarshal(p.Data, &h); err != nil {
		return nil, fmt.Errorf("engine.io: bad open packet: %w", err)
	}
	if h.SID == "" {
		return nil, errors.New("engine.io: open packet without sid")
	}
	if h.PingInterval <= 0 {
		h.PingInterval = 25000
	}
	if h.PingTimeout <= 0 {
		h.PingTimeout = 20000
	}
	return &h, nil
}

// PacketType is a Socket.IO v5 packet type.
type PacketType int

// Socket.IO v5 packet types.
const (
	PacketConnect PacketType = iota
	PacketDisconnect
	PacketEvent
	PacketAck
	PacketConnectError
	PacketBinaryEvent
	PacketBinaryAck
)

var typeNames = [...]string{"CONNECT", "DISCONNECT", "EVENT", "ACK", "CONNECT_ERROR", "BINARY_EVENT", "BINARY_ACK"}

func (t PacketType) String() string {
	if t >= 0 && int(t) < len(typeNames) {
		return typeNames[t]
	}
	return "UNKNOWN(" + strconv.Itoa(int(t)) + ")"
}

// IsBinary reports whether the type carries binary attachments.
func (t PacketType) IsBinary() bool { return t == PacketBinaryEvent || t == PacketBinaryAck }

// Packet is a Socket.IO packet. For binary packets Attachments is the number
// of binary Engine.IO messages that follow the text packet; Buffers holds
// them once received (or to send).
type Packet struct {
	Type        PacketType
	Namespace   string
	ID          *int64
	Data        json.RawMessage
	Attachments int
	Buffers     [][]byte
}

// Encode renders the text part of the packet:
// <type>[<attachments>-][<namespace>,][<id>][<json>].
func (p *Packet) Encode() string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(p.Type)))
	if p.Type.IsBinary() {
		n := p.Attachments
		if len(p.Buffers) > 0 {
			n = len(p.Buffers)
		}
		sb.WriteString(strconv.Itoa(n))
		sb.WriteByte('-')
	}
	if p.Namespace != "" && p.Namespace != "/" {
		sb.WriteString(p.Namespace)
		sb.WriteByte(',')
	}
	if p.ID != nil {
		sb.WriteString(strconv.FormatInt(*p.ID, 10))
	}
	if len(p.Data) > 0 {
		sb.Write(p.Data)
	}
	return sb.String()
}

// EnginePackets returns the Engine.IO packets carrying p (one text message
// followed by one binary message per attachment).
func (p *Packet) EnginePackets() []EPacket {
	out := []EPacket{TextPacket(EMessage, p.Encode())}
	for _, b := range p.Buffers {
		out = append(out, BinaryPacket(b))
	}
	return out
}

// DecodePacket parses the text part of a Socket.IO packet.
func DecodePacket(s string) (*Packet, error) {
	if s == "" {
		return nil, errors.New("socket.io: empty packet")
	}
	if s[0] < '0' || s[0] > '6' {
		return nil, fmt.Errorf("socket.io: unknown packet type %q", s[0])
	}
	p := &Packet{Type: PacketType(s[0] - '0'), Namespace: "/"}
	i := 1
	if p.Type.IsBinary() {
		j := strings.IndexByte(s[i:], '-')
		if j < 0 {
			return nil, errors.New("socket.io: binary packet without attachment count")
		}
		n, err := strconv.Atoi(s[i : i+j])
		if err != nil || n < 0 {
			return nil, fmt.Errorf("socket.io: bad attachment count %q", s[i:i+j])
		}
		p.Attachments = n
		i += j + 1
	}
	if i < len(s) && s[i] == '/' {
		j := strings.IndexByte(s[i:], ',')
		if j < 0 {
			p.Namespace = s[i:]
			i = len(s)
		} else {
			p.Namespace = s[i : i+j]
			i += j + 1
		}
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > start {
		id, err := strconv.ParseInt(s[start:i], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("socket.io: bad ack id: %w", err)
		}
		p.ID = &id
	}
	if i < len(s) {
		data := json.RawMessage(s[i:])
		if !json.Valid(data) {
			return nil, fmt.Errorf("socket.io: invalid JSON payload in %s packet", p.Type)
		}
		p.Data = data
	}
	return p, nil
}

// Placeholder returns the placeholder object for attachment num.
func Placeholder(num int) map[string]any {
	return map[string]any{"_placeholder": true, "num": num}
}

// HasPlaceholder reports whether v contains a binary placeholder object.
func HasPlaceholder(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if ph, ok := t["_placeholder"].(bool); ok && ph {
			return true
		}
		for _, e := range t {
			if HasPlaceholder(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if HasPlaceholder(e) {
				return true
			}
		}
	}
	return false
}

// Reconstruct replaces placeholder objects in v with repl(buffer). It
// returns an error when a placeholder references a missing attachment.
func Reconstruct(v any, bufs [][]byte, repl func([]byte) any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		if ph, ok := t["_placeholder"].(bool); ok && ph {
			n, err := placeholderNum(t["num"])
			if err != nil {
				return nil, err
			}
			if n < 0 || n >= len(bufs) {
				return nil, fmt.Errorf("socket.io: placeholder references attachment %d of %d", n, len(bufs))
			}
			return repl(bufs[n]), nil
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			r, err := Reconstruct(e, bufs, repl)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			r, err := Reconstruct(e, bufs, repl)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return v, nil
}

func placeholderNum(v any) (int, error) {
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case int:
		return n, nil
	}
	return 0, fmt.Errorf("socket.io: placeholder without numeric num")
}

// DecodeJSON unmarshals data preserving numbers as json.Number.
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// BinaryValue is how a received binary attachment is represented in
// decoded JSON arguments.
func BinaryValue(b []byte) any {
	return map[string]any{"_binary": true, "size": len(b), "base64": base64.StdEncoding.EncodeToString(b)}
}
