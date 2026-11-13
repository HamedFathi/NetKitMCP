package sio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/wsx"
)

// Transport names.
const (
	TransportWebSocket = "websocket"
	TransportPolling   = "polling"
)

// ErrClosed is returned when using a closed engine.
var ErrClosed = errors.New("engine.io connection closed")

// EngineConfig configures an Engine.IO connection.
type EngineConfig struct {
	// URL is the endpoint URL including the path (e.g.
	// http://host/socket.io/) and any extra query parameters. ws/wss
	// schemes are accepted.
	URL string
	// HTTPClient is the guarded client used for polling requests and the
	// websocket handshake. Give it a cookie jar for sticky sessions.
	HTTPClient *http.Client
	// Header holds extra request headers (sent on every request).
	Header http.Header
	// Origin is sent as the Origin header when set.
	Origin string
	// Transport is "websocket" (default) or "polling".
	Transport string
	// Upgrade allows a polling connection to upgrade to websocket.
	Upgrade bool
	// Compression negotiates permessage-deflate on websocket.
	Compression bool
	// ReadLimit bounds one websocket frame / polling response (0 = 1 MiB).
	ReadLimit int64
	// OnPacket receives message packets (text and binary) in order.
	OnPacket func(EPacket)
	// OnClose is called once when the connection ends; err is nil when the
	// connection was closed locally.
	OnClose func(err error)
}

// Engine is an Engine.IO v4 client connection.
type Engine struct {
	cfg       EngineConfig
	base      *url.URL
	HS        *Handshake
	RespHeads http.Header

	ctx    context.Context
	cancel context.CancelFunc

	sendMu    sync.Mutex // serialises writes and POSTs
	mu        sync.Mutex
	transport string
	ws        *websocket.Conn
	upgraded  bool

	pausePoll atomic.Bool
	closing   atomic.Bool
	pollDone  chan struct{}
	lastSeen  atomic.Int64
	pings     atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

// DialEngine opens an Engine.IO connection.
func DialEngine(ctx context.Context, cfg EngineConfig) (*Engine, error) {
	if cfg.HTTPClient == nil {
		return nil, errors.New("engine.io: HTTPClient is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "ws":
		u.Scheme = "http"
	case "https", "wss":
		u.Scheme = "https"
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q (use http, https, ws or wss)", u.Scheme)
	}
	if cfg.ReadLimit <= 0 {
		cfg.ReadLimit = 1 << 20
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportWebSocket
	}
	e := &Engine{cfg: cfg, base: u, closed: make(chan struct{}), pollDone: make(chan struct{})}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	switch cfg.Transport {
	case TransportWebSocket:
		close(e.pollDone)
		err = e.openWebSocket(ctx)
	case TransportPolling:
		err = e.openPolling(ctx)
	default:
		err = fmt.Errorf("transport must be websocket or polling, got %q", cfg.Transport)
	}
	if err != nil {
		e.cancel()
		return nil, err
	}
	go e.watchdog()
	return e, nil
}

// Transport returns the current transport name.
func (e *Engine) Transport() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.transport
}

// Upgraded reports whether the connection was upgraded from polling.
func (e *Engine) Upgraded() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.upgraded
}

// PingsAnswered returns how many server pings were answered.
func (e *Engine) PingsAnswered() int64 { return e.pings.Load() }

// Done is closed when the connection has ended.
func (e *Engine) Done() <-chan struct{} { return e.closed }

// Err returns why the connection ended (nil if open or closed locally).
func (e *Engine) Err() error {
	select {
	case <-e.closed:
		return e.closeErr
	default:
		return nil
	}
}

func (e *Engine) endpoint(transport, sid string) string {
	u := *e.base
	q := u.Query()
	q.Set("EIO", "4")
	q.Set("transport", transport)
	if sid != "" {
		q.Set("sid", sid)
	}
	if transport == TransportPolling {
		q.Set("t", strconv.FormatInt(time.Now().UnixNano(), 36))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (e *Engine) dialWS(ctx context.Context, sid string) (*websocket.Conn, *wsx.HandshakeInfo, error) {
	return wsx.Dial(ctx, wsx.Options{
		URL:         e.endpoint(TransportWebSocket, sid),
		HTTPClient:  e.cfg.HTTPClient,
		Header:      e.cfg.Header,
		Origin:      e.cfg.Origin,
		Compression: e.cfg.Compression,
		ReadLimit:   e.cfg.ReadLimit,
	})
}

func (e *Engine) openWebSocket(ctx context.Context) error {
	conn, info, err := e.dialWS(ctx, "")
	if err != nil {
		return err
	}
	e.RespHeads = http.Header{}
	for k, v := range info.Headers {
		e.RespHeads.Set(k, v)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil {
		conn.CloseNow()
		return fmt.Errorf("engine.io: reading open packet: %w", err)
	}
	p, err := DecodeWSFrame(typ == websocket.MessageBinary, data)
	if err != nil {
		conn.CloseNow()
		return err
	}
	hs, err := ParseHandshake(p)
	if err != nil {
		conn.CloseNow()
		return err
	}
	e.HS = hs
	e.ws = conn
	e.transport = TransportWebSocket
	e.touch()
	go e.wsReader(conn)
	return nil
}

func (e *Engine) openPolling(ctx context.Context) error {
	pkts, hdr, err := e.pollRequest(ctx, "")
	if err != nil {
		return err
	}
	e.RespHeads = hdr
	if len(pkts) == 0 {
		return errors.New("engine.io: empty handshake response")
	}
	hs, err := ParseHandshake(pkts[0])
	if err != nil {
		return err
	}
	e.HS = hs
	e.transport = TransportPolling
	e.touch()
	for _, p := range pkts[1:] {
		e.dispatch(p)
	}
	go e.pollLoop()
	if e.cfg.Upgrade && contains(hs.Upgrades, TransportWebSocket) {
		if err := e.upgrade(ctx); err != nil {
			e.shutdown(err)
			return fmt.Errorf("engine.io: upgrade to websocket failed: %w", err)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (e *Engine) touch() { e.lastSeen.Store(time.Now().UnixNano()) }

func (e *Engine) pollRequest(ctx context.Context, sid string) ([]EPacket, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint(TransportPolling, sid), nil)
	if err != nil {
		return nil, nil, err
	}
	e.applyHeaders(req)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("engine.io polling request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, e.cfg.ReadLimit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("engine.io polling read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, fmt.Errorf("engine.io polling: HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	if int64(len(body)) > e.cfg.ReadLimit {
		return nil, resp.Header, fmt.Errorf("engine.io polling payload exceeds %d bytes", e.cfg.ReadLimit)
	}
	pkts, err := DecodePolling(body)
	return pkts, resp.Header, err
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func (e *Engine) applyHeaders(req *http.Request) {
	for k, vs := range e.cfg.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if e.cfg.Origin != "" {
		req.Header.Set("Origin", e.cfg.Origin)
	}
}

func (e *Engine) pollLoop() {
	defer close(e.pollDone)
	for {
		if e.pausePoll.Load() {
			return
		}
		select {
		case <-e.closed:
			return
		default:
		}
		pkts, _, err := e.pollRequest(e.ctx, e.HS.SID)
		if err != nil {
			if e.closing.Load() {
				e.shutdown(nil)
			} else if e.ctx.Err() == nil {
				e.shutdown(err)
			}
			return
		}
		for _, p := range pkts {
			e.dispatch(p)
		}
	}
}

func (e *Engine) wsReader(conn *websocket.Conn) {
	for {
		typ, data, err := conn.Read(e.ctx)
		if err != nil {
			if e.closing.Load() {
				e.shutdown(nil)
				return
			}
			if ci := wsx.CloseInfo(err); ci != nil {
				err = fmt.Errorf("websocket closed by server (code %d %s)", ci.Code, ci.Reason)
			}
			e.shutdown(err)
			return
		}
		p, err := DecodeWSFrame(typ == websocket.MessageBinary, data)
		if err != nil {
			continue
		}
		e.dispatch(p)
	}
}

func (e *Engine) dispatch(p EPacket) {
	e.touch()
	if p.Binary {
		if e.cfg.OnPacket != nil {
			e.cfg.OnPacket(p)
		}
		return
	}
	switch p.Type {
	case EPing:
		e.pings.Add(1)
		go e.Send(e.ctx, TextPacket(EPong, string(p.Data)))
	case EClose:
		if e.closing.Load() {
			e.shutdown(nil)
		} else {
			e.shutdown(errors.New("engine.io connection closed by server"))
		}
	case EMessage:
		if e.cfg.OnPacket != nil {
			e.cfg.OnPacket(p)
		}
	}
}

func (e *Engine) watchdog() {
	limit := time.Duration(e.HS.PingInterval+e.HS.PingTimeout) * time.Millisecond
	t := time.NewTicker(limit / 10)
	defer t.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-t.C:
			if time.Since(time.Unix(0, e.lastSeen.Load())) > limit {
				e.shutdown(fmt.Errorf("engine.io ping timeout: nothing received for %s", limit))
				return
			}
		}
	}
}

// upgrade probes and switches a polling connection to websocket.
func (e *Engine) upgrade(ctx context.Context) error {
	conn, _, err := e.dialWS(ctx, e.HS.SID)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		conn.CloseNow()
		return err
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("2probe")); err != nil {
		return fail(err)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return fail(fmt.Errorf("waiting for probe response: %w", err))
	}
	if typ != websocket.MessageText || string(data) != "3probe" {
		return fail(fmt.Errorf("unexpected probe response %q", data))
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	e.pausePoll.Store(true)
	select {
	case <-e.pollDone:
	case <-ctx.Done():
		return fail(errors.New("timed out waiting for the polling request to finish"))
	case <-e.closed:
		return fail(ErrClosed)
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte{EUpgrade}); err != nil {
		return fail(err)
	}
	e.mu.Lock()
	e.ws = conn
	e.transport = TransportWebSocket
	e.upgraded = true
	e.mu.Unlock()
	go e.wsReader(conn)
	return nil
}

// Send writes packets on the current transport.
func (e *Engine) Send(ctx context.Context, pkts ...EPacket) error {
	select {
	case <-e.closed:
		return ErrClosed
	default:
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	e.mu.Lock()
	ws, tr := e.ws, e.transport
	e.mu.Unlock()
	if tr == TransportWebSocket {
		for _, p := range pkts {
			bin, payload := p.WSFrame()
			typ := websocket.MessageText
			if bin {
				typ = websocket.MessageBinary
			}
			if err := ws.Write(ctx, typ, payload); err != nil {
				return fmt.Errorf("engine.io websocket write: %w", err)
			}
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint(TransportPolling, e.HS.SID), bytes.NewReader(EncodePolling(pkts)))
	if err != nil {
		return err
	}
	e.applyHeaders(req)
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("engine.io polling POST: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine.io polling POST: HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	return nil
}

// Close sends a close packet and tears the connection down.
func (e *Engine) Close() error {
	select {
	case <-e.closed:
		return nil
	default:
	}
	e.closing.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = e.Send(ctx, TextPacket(EClose, ""))
	e.mu.Lock()
	ws := e.ws
	e.mu.Unlock()
	if ws != nil {
		done := make(chan struct{})
		go func() { ws.Close(websocket.StatusNormalClosure, ""); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			ws.CloseNow()
		}
	}
	e.shutdown(nil)
	return nil
}

func (e *Engine) shutdown(err error) {
	e.closeOnce.Do(func() {
		e.closeErr = err
		close(e.closed)
		e.cancel()
		e.mu.Lock()
		ws := e.ws
		e.mu.Unlock()
		if ws != nil && err != nil {
			ws.CloseNow()
		}
		if e.cfg.OnClose != nil {
			go e.cfg.OnClose(err)
		}
	})
}
