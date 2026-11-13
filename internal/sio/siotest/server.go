// Package siotest is a minimal in-process Engine.IO v4 / Socket.IO v5 server
// for tests. It supports the polling and websocket transports (including the
// polling-to-websocket upgrade), server pings, namespaces, a CONNECT auth
// check, acks in both directions and binary attachments.
//
// Event behaviour:
//   - any event carrying an ack id is acknowledged with the same args;
//   - "echo" is emitted back as "echo" with the same args (and attachments);
//   - "ask" makes the server emit "question" with an ack id; when the client
//     acks it, the server emits "answer" with the ack args;
//   - "whoami" emits "whoami" with namespace, auth payload and request headers;
//   - "kick" makes the server disconnect the namespace;
//   - "flood" with a number N emits N "tick" events;
//   - "bye" closes the Engine.IO connection.
package siotest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/sio"
)

// Server is the test server. Configure fields before serving.
type Server struct {
	PingInterval time.Duration // default 300ms
	PingTimeout  time.Duration // default 2s
	// Namespaces lists the namespaces (besides "/") clients may join;
	// nil allows any.
	Namespaces []string
	// AuthToken, when set, requires the CONNECT auth payload {"token": AuthToken}.
	AuthToken string
	// NoUpgrade disables offering the websocket upgrade to polling clients.
	NoUpgrade bool

	Pongs        atomic.Int64
	Upgrades     atomic.Int64
	CookieMisses atomic.Int64

	mu       sync.Mutex
	sessions map[string]*session
	headers  http.Header
}

// LastHeaders returns the request headers of the latest handshake.
func (s *Server) LastHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers.Clone()
}

type session struct {
	srv       *Server
	sid       string
	headers   http.Header
	mu        sync.Mutex
	queue     []sio.EPacket
	notify    chan struct{}
	transport string
	upgrading bool
	closed    chan struct{}
	closeOnce sync.Once
	pending   *sio.Packet
	nsps      map[string]json.RawMessage
	nextAck   int64
	asks      map[int64]string // ack id -> namespace
}

func randID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) newSession(r *http.Request, transport string) *session {
	ss := &session{
		srv: s, sid: randID(), headers: r.Header.Clone(), notify: make(chan struct{}, 1),
		transport: transport, closed: make(chan struct{}), nsps: map[string]json.RawMessage{}, asks: map[int64]string{},
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[string]*session{}
	}
	s.sessions[ss.sid] = ss
	s.headers = r.Header.Clone()
	s.mu.Unlock()
	go ss.pinger()
	return ss
}

func (s *Server) pingInterval() time.Duration {
	if s.PingInterval > 0 {
		return s.PingInterval
	}
	return 300 * time.Millisecond
}

func (s *Server) pingTimeout() time.Duration {
	if s.PingTimeout > 0 {
		return s.PingTimeout
	}
	return 2 * time.Second
}

func (s *Server) handshake(ss *session, polling bool) sio.EPacket {
	ups := []string{}
	if polling && !s.NoUpgrade {
		ups = []string{"websocket"}
	}
	b, _ := json.Marshal(sio.Handshake{SID: ss.sid, Upgrades: ups, PingInterval: int(s.pingInterval() / time.Millisecond),
		PingTimeout: int(s.pingTimeout() / time.Millisecond), MaxPayload: 1000000})
	return sio.EPacket{Type: sio.EOpen, Data: b}
}

// ServeHTTP implements the Engine.IO endpoint (mount it on /socket.io/).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("EIO") != "4" {
		http.Error(w, `{"code":5,"message":"Unsupported protocol version"}`, http.StatusBadRequest)
		return
	}
	sid := q.Get("sid")
	var ss *session
	if sid != "" {
		s.mu.Lock()
		ss = s.sessions[sid]
		s.mu.Unlock()
		if ss == nil {
			http.Error(w, `{"code":1,"message":"Session ID unknown"}`, http.StatusBadRequest)
			return
		}
		if c, err := r.Cookie("io"); err != nil || c.Value != sid {
			s.CookieMisses.Add(1)
		}
	}
	switch q.Get("transport") {
	case "polling":
		if ss == nil {
			if r.Method != http.MethodGet {
				http.Error(w, "bad handshake method", http.StatusBadRequest)
				return
			}
			ss = s.newSession(r, "polling")
			http.SetCookie(w, &http.Cookie{Name: "io", Value: ss.sid, Path: "/"})
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.Write(sio.EncodePolling([]sio.EPacket{s.handshake(ss, true)}))
			return
		}
		switch r.Method {
		case http.MethodGet:
			ss.servePollGet(w, r)
		case http.MethodPost:
			ss.servePollPost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "websocket":
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.SetReadLimit(1 << 20)
		if ss == nil {
			ss = s.newSession(r, "websocket")
			ss.serveWS(c, true)
		} else {
			ss.serveUpgrade(c)
		}
	default:
		http.Error(w, `{"code":0,"message":"Transport unknown"}`, http.StatusBadRequest)
	}
}

func (ss *session) send(pkts ...sio.EPacket) {
	ss.mu.Lock()
	ss.queue = append(ss.queue, pkts...)
	ss.mu.Unlock()
	select {
	case ss.notify <- struct{}{}:
	default:
	}
}

func (ss *session) take() []sio.EPacket {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	q := ss.queue
	ss.queue = nil
	return q
}

func (ss *session) close() {
	ss.closeOnce.Do(func() {
		close(ss.closed)
		ss.srv.mu.Lock()
		delete(ss.srv.sessions, ss.sid)
		ss.srv.mu.Unlock()
	})
}

func (ss *session) pinger() {
	t := time.NewTicker(ss.srv.pingInterval())
	defer t.Stop()
	for {
		select {
		case <-ss.closed:
			return
		case <-t.C:
			ss.send(sio.TextPacket(sio.EPing, ""))
		}
	}
}

func (ss *session) servePollGet(w http.ResponseWriter, r *http.Request) {
	ss.mu.Lock()
	tr := ss.transport
	ss.mu.Unlock()
	if tr != "polling" {
		http.Error(w, "transport upgraded", http.StatusBadRequest)
		return
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		ss.mu.Lock()
		n, upgrading := len(ss.queue), ss.upgrading
		ss.mu.Unlock()
		if n > 0 {
			break
		}
		if upgrading {
			w.Write(sio.EncodePolling([]sio.EPacket{sio.TextPacket(sio.ENoop, "")}))
			return
		}
		select {
		case <-ss.notify:
		case <-tick.C:
		case <-ss.closed:
			w.Write(sio.EncodePolling([]sio.EPacket{sio.TextPacket(sio.EClose, "")}))
			return
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Write(sio.EncodePolling(ss.take()))
}

func (ss *session) servePollPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pkts, err := sio.DecodePolling(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range pkts {
		ss.handleEngine(p)
	}
	w.Write([]byte("ok"))
}

func (ss *session) serveUpgrade(c *websocket.Conn) {
	ctx := context.Background()
	typ, data, err := c.Read(ctx)
	if err != nil || typ != websocket.MessageText || string(data) != "2probe" {
		c.Close(websocket.StatusProtocolError, "expected probe")
		return
	}
	if err := c.Write(ctx, websocket.MessageText, []byte("3probe")); err != nil {
		return
	}
	ss.mu.Lock()
	ss.upgrading = true
	ss.mu.Unlock()
	typ, data, err = c.Read(ctx)
	if err != nil || typ != websocket.MessageText || string(data) != "5" {
		c.Close(websocket.StatusProtocolError, "expected upgrade")
		return
	}
	ss.mu.Lock()
	ss.transport = "websocket"
	ss.upgrading = false
	ss.mu.Unlock()
	ss.srv.Upgrades.Add(1)
	ss.serveWS(c, false)
}

func (ss *session) serveWS(c *websocket.Conn, sendOpen bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ss.close()
	if sendOpen {
		bin, payload := ss.srv.handshake(ss, false).WSFrame()
		_ = bin
		if err := c.Write(ctx, websocket.MessageText, payload); err != nil {
			return
		}
	}
	go func() {
		for {
			for _, p := range ss.take() {
				bin, payload := p.WSFrame()
				typ := websocket.MessageText
				if bin {
					typ = websocket.MessageBinary
				}
				if err := c.Write(ctx, typ, payload); err != nil {
					return
				}
				if !p.Binary && p.Type == sio.EClose {
					c.Close(websocket.StatusNormalClosure, "")
					return
				}
			}
			select {
			case <-ss.notify:
			case <-ss.closed:
				ss.mu.Lock()
				left := len(ss.queue)
				ss.mu.Unlock()
				if left == 0 {
					c.Close(websocket.StatusNormalClosure, "")
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Wake the writer for anything queued before the switch.
	select {
	case ss.notify <- struct{}{}:
	default:
	}
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		p, err := sio.DecodeWSFrame(typ == websocket.MessageBinary, data)
		if err != nil {
			continue
		}
		ss.handleEngine(p)
	}
}

func (ss *session) handleEngine(p sio.EPacket) {
	if p.Binary {
		ss.mu.Lock()
		pk := ss.pending
		if pk != nil {
			pk.Buffers = append(pk.Buffers, p.Data)
			if len(pk.Buffers) >= pk.Attachments {
				ss.pending = nil
			} else {
				pk = nil
			}
		}
		ss.mu.Unlock()
		if pk != nil {
			ss.handleSIO(pk)
		}
		return
	}
	switch p.Type {
	case sio.EPong:
		ss.srv.Pongs.Add(1)
	case sio.EClose:
		ss.close()
	case sio.EMessage:
		pk, err := sio.DecodePacket(string(p.Data))
		if err != nil {
			return
		}
		if pk.Type.IsBinary() && pk.Attachments > 0 {
			ss.mu.Lock()
			ss.pending = pk
			ss.mu.Unlock()
			return
		}
		ss.handleSIO(pk)
	}
}

func (ss *session) sendPacket(pk *sio.Packet) { ss.send(pk.EnginePackets()...) }

func (ss *session) connectError(ns, msg string) {
	b, _ := json.Marshal(map[string]any{"message": msg, "data": map[string]any{"namespace": ns}})
	ss.sendPacket(&sio.Packet{Type: sio.PacketConnectError, Namespace: ns, Data: b})
}

func (ss *session) emit(ns string, args []json.RawMessage, bufs [][]byte, ackID *int64) {
	data, _ := json.Marshal(args)
	pk := &sio.Packet{Type: sio.PacketEvent, Namespace: ns, Data: data, Buffers: bufs, ID: ackID}
	if len(bufs) > 0 {
		pk.Type = sio.PacketBinaryEvent
	}
	ss.sendPacket(pk)
}

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (ss *session) handleSIO(pk *sio.Packet) {
	ns := pk.Namespace
	switch pk.Type {
	case sio.PacketConnect:
		if ns != "/" && ss.srv.Namespaces != nil {
			ok := false
			for _, n := range ss.srv.Namespaces {
				ok = ok || n == ns
			}
			if !ok {
				ss.connectError(ns, "Invalid namespace")
				return
			}
		}
		if ss.srv.AuthToken != "" {
			var a struct {
				Token string `json:"token"`
			}
			_ = json.Unmarshal(pk.Data, &a)
			if a.Token != ss.srv.AuthToken {
				ss.connectError(ns, "not authorized")
				return
			}
		}
		ss.mu.Lock()
		ss.nsps[ns] = pk.Data
		ss.mu.Unlock()
		ss.sendPacket(&sio.Packet{Type: sio.PacketConnect, Namespace: ns, Data: raw(map[string]string{"sid": randID()})})
	case sio.PacketDisconnect:
		ss.mu.Lock()
		delete(ss.nsps, ns)
		ss.mu.Unlock()
	case sio.PacketEvent, sio.PacketBinaryEvent:
		ss.mu.Lock()
		auth, joined := ss.nsps[ns]
		ss.mu.Unlock()
		if !joined {
			return
		}
		var arr []json.RawMessage
		if json.Unmarshal(pk.Data, &arr) != nil || len(arr) == 0 {
			return
		}
		var name string
		json.Unmarshal(arr[0], &name)
		args := arr[1:]
		if pk.ID != nil {
			data, _ := json.Marshal(args)
			ack := &sio.Packet{Type: sio.PacketAck, Namespace: ns, ID: pk.ID, Data: data, Buffers: pk.Buffers}
			if len(pk.Buffers) > 0 {
				ack.Type = sio.PacketBinaryAck
			}
			ss.sendPacket(ack)
		}
		switch name {
		case "echo":
			ss.emit(ns, append([]json.RawMessage{raw("echo")}, args...), pk.Buffers, nil)
		case "ask":
			ss.mu.Lock()
			id := ss.nextAck
			ss.nextAck++
			ss.asks[id] = ns
			ss.mu.Unlock()
			ss.emit(ns, []json.RawMessage{raw("question"), raw("what?")}, nil, &id)
		case "whoami":
			if auth == nil {
				auth = raw(nil)
			}
			info := map[string]any{
				"namespace":     ns,
				"auth":          auth,
				"origin":        ss.headers.Get("Origin"),
				"authorization": ss.headers.Get("Authorization"),
				"x_custom":      ss.headers.Get("X-Custom"),
			}
			ss.emit(ns, []json.RawMessage{raw("whoami"), raw(info)}, nil, nil)
		case "kick":
			ss.mu.Lock()
			delete(ss.nsps, ns)
			ss.mu.Unlock()
			ss.sendPacket(&sio.Packet{Type: sio.PacketDisconnect, Namespace: ns})
		case "flood":
			n := 0
			if len(args) > 0 {
				n, _ = strconv.Atoi(string(args[0]))
			}
			for i := 0; i < n; i++ {
				ss.emit(ns, []json.RawMessage{raw("tick"), raw(i)}, nil, nil)
			}
		case "bye":
			ss.send(sio.TextPacket(sio.EClose, ""))
			go func() { time.Sleep(200 * time.Millisecond); ss.close() }()
		}
	case sio.PacketAck, sio.PacketBinaryAck:
		if pk.ID == nil {
			return
		}
		ss.mu.Lock()
		ans, ok := ss.asks[*pk.ID]
		delete(ss.asks, *pk.ID)
		ss.mu.Unlock()
		if !ok || ans != ns {
			return
		}
		var args []json.RawMessage
		json.Unmarshal(pk.Data, &args)
		ss.emit(ns, append([]json.RawMessage{raw("answer")}, args...), pk.Buffers, nil)
	}
}

// Close ends every session (stopping their ping goroutines).
func (s *Server) Close() {
	s.mu.Lock()
	var all []*session
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.Unlock()
	for _, ss := range all {
		ss.close()
	}
}

// Sessions returns the number of open sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
