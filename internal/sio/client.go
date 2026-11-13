package sio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Message kinds delivered to Config.OnMessage.
const (
	KindEvent        = "event"
	KindAck          = "ack"
	KindConnect      = "connect"
	KindConnectError = "connect_error"
	KindDisconnect   = "disconnect"
	KindError        = "error"
	KindClose        = "close"
)

// Message is something received from the server.
type Message struct {
	Kind        string
	Namespace   string
	Event       string          // event name for KindEvent
	Data        json.RawMessage // event args (array), ack args (array), connect data / error (object)
	AckID       *int64          // ack id of an ACK, or the id the server wants acknowledged for an EVENT
	Attachments int
	Err         string // for KindError / KindClose
}

// Namespace states.
const (
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateError        = "connect_error"
	StateDisconnected = "disconnected"
)

// NamespaceInfo describes one namespace on the connection.
type NamespaceInfo struct {
	Namespace string `json:"namespace"`
	State     string `json:"state"`
	SID       string `json:"sid,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Config configures a Socket.IO client.
type Config struct {
	Engine EngineConfig
	// OnMessage receives events, acks (not claimed by a synchronous waiter),
	// server-initiated disconnects, decode errors and the final close.
	// It is called from the reader goroutine and must not block for long.
	OnMessage func(Message)
}

// Client is a Socket.IO v5 client over one Engine.IO connection.
type Client struct {
	eng       *Engine
	onMessage func(Message)

	mu         sync.Mutex
	nsps       map[string]*NamespaceInfo
	connWait   map[string]chan Message
	ackWait    map[string]chan Message
	nextID     map[string]int64
	pending    *Packet
	closedOnce sync.Once
}

// Dial opens the Engine.IO connection. Namespaces are joined with Connect.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	c := &Client{
		onMessage: cfg.OnMessage,
		nsps:      map[string]*NamespaceInfo{},
		connWait:  map[string]chan Message{},
		ackWait:   map[string]chan Message{},
		nextID:    map[string]int64{},
	}
	ec := cfg.Engine
	ec.OnPacket = c.onPacket
	ec.OnClose = c.onClose
	eng, err := DialEngine(ctx, ec)
	if err != nil {
		return nil, err
	}
	c.eng = eng
	return c, nil
}

// Engine returns the underlying Engine.IO connection.
func (c *Client) Engine() *Engine { return c.eng }

// Done is closed when the connection ends.
func (c *Client) Done() <-chan struct{} { return c.eng.Done() }

// NormalizeNamespace returns "/" for empty and adds a leading slash.
func NormalizeNamespace(ns string) string {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return "/"
	}
	if !strings.HasPrefix(ns, "/") {
		ns = "/" + ns
	}
	return ns
}

// Namespaces returns a snapshot of namespace states.
func (c *Client) Namespaces() []NamespaceInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]NamespaceInfo, 0, len(c.nsps))
	for _, n := range c.nsps {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace < out[j].Namespace })
	return out
}

// ConnectError is returned by Connect when the server refuses a namespace.
type ConnectError struct {
	Namespace string
	Data      json.RawMessage
}

func (e *ConnectError) Error() string {
	msg := string(e.Data)
	var obj struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(e.Data, &obj) == nil && obj.Message != "" {
		msg = obj.Message
	}
	return fmt.Sprintf("socket.io connect_error on namespace %s: %s", e.Namespace, msg)
}

// Connect joins a namespace with an optional auth payload and waits for the
// server's CONNECT or CONNECT_ERROR.
func (c *Client) Connect(ctx context.Context, ns string, auth any) (*NamespaceInfo, error) {
	ns = NormalizeNamespace(ns)
	pkt := &Packet{Type: PacketConnect, Namespace: ns}
	if auth != nil {
		b, err := json.Marshal(auth)
		if err != nil {
			return nil, fmt.Errorf("auth payload: %w", err)
		}
		if len(b) == 0 || b[0] != '{' {
			return nil, errors.New("auth payload must be a JSON object")
		}
		pkt.Data = b
	}
	ch := make(chan Message, 1)
	c.mu.Lock()
	if n := c.nsps[ns]; n != nil && n.State == StateConnected {
		cp := *n
		c.mu.Unlock()
		return &cp, nil
	}
	c.nsps[ns] = &NamespaceInfo{Namespace: ns, State: StateConnecting}
	c.connWait[ns] = ch
	c.mu.Unlock()
	cleanup := func() {
		c.mu.Lock()
		if c.connWait[ns] == ch {
			delete(c.connWait, ns)
		}
		c.mu.Unlock()
	}
	if err := c.eng.Send(ctx, pkt.EnginePackets()...); err != nil {
		cleanup()
		return nil, err
	}
	select {
	case m := <-ch:
		c.mu.Lock()
		info := *c.nsps[ns]
		c.mu.Unlock()
		if m.Kind == KindConnectError {
			return &info, &ConnectError{Namespace: ns, Data: m.Data}
		}
		return &info, nil
	case <-ctx.Done():
		cleanup()
		return nil, fmt.Errorf("timed out waiting for the server to accept namespace %s", ns)
	case <-c.eng.Done():
		cleanup()
		return nil, closedErr(c.eng)
	}
}

func closedErr(e *Engine) error {
	if err := e.Err(); err != nil {
		return err
	}
	return ErrClosed
}

// Emitted describes a sent event or ack.
type Emitted struct {
	Namespace string
	Packet    *Packet
	AckID     *int64
	waiter    chan Message
	key       string
}

// EmitOptions control Emit.
type EmitOptions struct {
	// Ack requests an acknowledgement.
	Ack bool
	// Wait registers a synchronous waiter for the ack (use AwaitAck). When
	// false, the ack is delivered through OnMessage.
	Wait bool
}

func ackKey(ns string, id int64) string { return ns + "#" + strconv.FormatInt(id, 10) }

// BuildArgs builds the JSON array for an event or ack, appending
// placeholders for buffers unless args already contain them.
func BuildArgs(prefix []any, args []any, bufs [][]byte) (json.RawMessage, error) {
	arr := append(append([]any{}, prefix...), args...)
	if len(bufs) > 0 && !HasPlaceholder(args) {
		for i := range bufs {
			arr = append(arr, Placeholder(i))
		}
	}
	b, err := json.Marshal(arr)
	if err != nil {
		return nil, fmt.Errorf("event args: %w", err)
	}
	return b, nil
}

func (c *Client) requireConnected(ns string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nsps[ns]
	if n == nil || n.State != StateConnected {
		state := "not joined"
		if n != nil {
			state = n.State
		}
		return fmt.Errorf("namespace %s is %s; connect it first", ns, state)
	}
	return nil
}

// Emit sends an event on a connected namespace.
func (c *Client) Emit(ctx context.Context, ns, event string, args []any, bufs [][]byte, o EmitOptions) (*Emitted, error) {
	ns = NormalizeNamespace(ns)
	if event == "" {
		return nil, errors.New("event name is required")
	}
	if err := c.requireConnected(ns); err != nil {
		return nil, err
	}
	data, err := BuildArgs([]any{event}, args, bufs)
	if err != nil {
		return nil, err
	}
	pkt := &Packet{Type: PacketEvent, Namespace: ns, Data: data, Buffers: bufs}
	if len(bufs) > 0 {
		pkt.Type = PacketBinaryEvent
	}
	em := &Emitted{Namespace: ns, Packet: pkt}
	if o.Ack || o.Wait {
		c.mu.Lock()
		id := c.nextID[ns]
		c.nextID[ns] = id + 1
		pkt.ID = &id
		em.AckID = &id
		em.key = ackKey(ns, id)
		if o.Wait {
			em.waiter = make(chan Message, 1)
			c.ackWait[em.key] = em.waiter
		}
		c.mu.Unlock()
	}
	if err := c.eng.Send(ctx, pkt.EnginePackets()...); err != nil {
		if em.waiter != nil {
			c.mu.Lock()
			delete(c.ackWait, em.key)
			c.mu.Unlock()
		}
		return nil, err
	}
	return em, nil
}

// AwaitAck waits for the ack of an event emitted with Wait. On timeout the
// waiter is removed and a late ack is delivered through OnMessage.
func (c *Client) AwaitAck(ctx context.Context, em *Emitted) (*Message, error) {
	if em.waiter == nil {
		return nil, errors.New("event was not emitted with a waiter")
	}
	select {
	case m := <-em.waiter:
		return &m, nil
	case <-ctx.Done():
	case <-c.eng.Done():
	}
	c.mu.Lock()
	_, still := c.ackWait[em.key]
	delete(c.ackWait, em.key)
	c.mu.Unlock()
	if !still {
		// Delivered concurrently.
		m := <-em.waiter
		return &m, nil
	}
	if c.eng.Err() != nil {
		return nil, closedErr(c.eng)
	}
	return nil, nil
}

// Ack answers a server ack request.
func (c *Client) Ack(ctx context.Context, ns string, id int64, args []any, bufs [][]byte) (*Packet, error) {
	ns = NormalizeNamespace(ns)
	if err := c.requireConnected(ns); err != nil {
		return nil, err
	}
	data, err := BuildArgs(nil, args, bufs)
	if err != nil {
		return nil, err
	}
	pkt := &Packet{Type: PacketAck, Namespace: ns, ID: &id, Data: data, Buffers: bufs}
	if len(bufs) > 0 {
		pkt.Type = PacketBinaryAck
	}
	return pkt, c.eng.Send(ctx, pkt.EnginePackets()...)
}

// Disconnect leaves a namespace.
func (c *Client) Disconnect(ctx context.Context, ns string) error {
	ns = NormalizeNamespace(ns)
	c.mu.Lock()
	n := c.nsps[ns]
	connected := n != nil && n.State == StateConnected
	if n != nil {
		n.State = StateDisconnected
	}
	c.mu.Unlock()
	if !connected {
		return nil
	}
	pkt := &Packet{Type: PacketDisconnect, Namespace: ns}
	return c.eng.Send(ctx, pkt.EnginePackets()...)
}

// Close leaves every connected namespace and closes the Engine.IO connection.
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, n := range c.Namespaces() {
		if n.State == StateConnected {
			_ = c.Disconnect(ctx, n.Namespace)
		}
	}
	return c.eng.Close()
}

func (c *Client) emit(m Message) {
	if c.onMessage != nil {
		c.onMessage(m)
	}
}

func (c *Client) onClose(err error) {
	c.closedOnce.Do(func() {
		m := Message{Kind: KindClose}
		if err != nil {
			m.Err = err.Error()
		}
		c.emit(m)
	})
}

func (c *Client) onPacket(p EPacket) {
	if p.Binary {
		c.mu.Lock()
		pk := c.pending
		if pk == nil {
			c.mu.Unlock()
			c.emit(Message{Kind: KindError, Err: "unexpected binary message without a pending binary packet"})
			return
		}
		pk.Buffers = append(pk.Buffers, p.Data)
		done := len(pk.Buffers) >= pk.Attachments
		if done {
			c.pending = nil
		}
		c.mu.Unlock()
		if done {
			c.handle(pk)
		}
		return
	}
	pk, err := DecodePacket(string(p.Data))
	if err != nil {
		c.emit(Message{Kind: KindError, Err: err.Error()})
		return
	}
	if pk.Type.IsBinary() && pk.Attachments > 0 {
		c.mu.Lock()
		c.pending = pk
		c.mu.Unlock()
		return
	}
	c.handle(pk)
}

func (c *Client) reconstruct(pk *Packet) (json.RawMessage, error) {
	if len(pk.Buffers) == 0 || len(pk.Data) == 0 {
		return pk.Data, nil
	}
	v, err := DecodeJSON(pk.Data)
	if err != nil {
		return nil, err
	}
	v, err = Reconstruct(v, pk.Buffers, BinaryValue)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (c *Client) handle(pk *Packet) {
	ns := pk.Namespace
	switch pk.Type {
	case PacketConnect, PacketConnectError:
		kind := KindConnect
		c.mu.Lock()
		n := c.nsps[ns]
		if n == nil {
			n = &NamespaceInfo{Namespace: ns}
			c.nsps[ns] = n
		}
		if pk.Type == PacketConnect {
			n.State = StateConnected
			n.Error = ""
			var d struct {
				SID string `json:"sid"`
			}
			_ = json.Unmarshal(pk.Data, &d)
			n.SID = d.SID
		} else {
			kind = KindConnectError
			n.State = StateError
			n.Error = (&ConnectError{Namespace: ns, Data: pk.Data}).Error()
		}
		ch := c.connWait[ns]
		delete(c.connWait, ns)
		c.mu.Unlock()
		m := Message{Kind: kind, Namespace: ns, Data: pk.Data}
		if ch != nil {
			ch <- m
		} else {
			c.emit(m)
		}
	case PacketDisconnect:
		c.mu.Lock()
		if n := c.nsps[ns]; n != nil {
			n.State = StateDisconnected
		}
		c.mu.Unlock()
		c.emit(Message{Kind: KindDisconnect, Namespace: ns})
	case PacketEvent, PacketBinaryEvent:
		data, err := c.reconstruct(pk)
		if err != nil {
			c.emit(Message{Kind: KindError, Namespace: ns, Err: err.Error()})
			return
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil || len(arr) == 0 {
			c.emit(Message{Kind: KindError, Namespace: ns, Err: "event payload is not a non-empty array"})
			return
		}
		var name string
		if err := json.Unmarshal(arr[0], &name); err != nil {
			c.emit(Message{Kind: KindError, Namespace: ns, Err: "event name is not a string"})
			return
		}
		args, _ := json.Marshal(arr[1:])
		c.emit(Message{Kind: KindEvent, Namespace: ns, Event: name, Data: args, AckID: pk.ID, Attachments: len(pk.Buffers)})
	case PacketAck, PacketBinaryAck:
		data, err := c.reconstruct(pk)
		if err != nil {
			c.emit(Message{Kind: KindError, Namespace: ns, Err: err.Error()})
			return
		}
		if len(data) == 0 {
			data = json.RawMessage("[]")
		}
		m := Message{Kind: KindAck, Namespace: ns, Data: data, AckID: pk.ID, Attachments: len(pk.Buffers)}
		if pk.ID != nil {
			c.mu.Lock()
			ch := c.ackWait[ackKey(ns, *pk.ID)]
			delete(c.ackWait, ackKey(ns, *pk.ID))
			c.mu.Unlock()
			if ch != nil {
				ch <- m
				return
			}
		}
		c.emit(m)
	}
}
