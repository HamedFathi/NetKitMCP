package wstools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
	"github.com/HamedFathi/NetKitMCP/internal/wsx"
)

// wsSession is an interactive WebSocket connection.
type wsSession struct {
	id      string
	conn    *websocket.Conn
	release func()
	buf     *session.Buffer
	hs      *wsx.HandshakeInfo
	target  string
	cancel  context.CancelFunc
	done    chan struct{}

	mu        sync.Mutex
	status    string // open | closed
	peerClose *types.CloseInfo
	sentClose *types.CloseInfo
	readErr   string

	sent, received  atomic.Int64
	pongs, pingFail atomic.Int64
	closeOnce       sync.Once
}

func (s *wsSession) reader(ctx context.Context) {
	defer close(s.done)
	for {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			ci := wsx.CloseInfo(err)
			s.mu.Lock()
			s.status = "closed"
			if ci != nil {
				s.peerClose = ci
			} else if ctx.Err() == nil && s.sentClose == nil {
				s.readErr = err.Error()
			}
			readErr := s.readErr
			s.mu.Unlock()
			if readErr != "" {
				s.buf.CloseWith(ci, errors.New(readErr))
			} else {
				s.buf.CloseWith(ci, nil)
			}
			return
		}
		s.received.Add(1)
		s.buf.Push(wsx.Message("in", typ, data))
	}
}

func (s *wsSession) keepalive(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, every)
			err := s.conn.Ping(pctx)
			cancel()
			if err != nil {
				s.pingFail.Add(1)
			} else {
				s.pongs.Add(1)
			}
		}
	}
}

// closeWith sends a close frame and releases resources.
func (s *wsSession) closeWith(code int, reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		open := s.status == "open"
		if open {
			s.sentClose = &types.CloseInfo{Code: code, Reason: reason}
		}
		s.mu.Unlock()
		if open {
			closeConn(s.conn, code, reason)
		}
		s.cancel()
		s.conn.CloseNow()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
		}
		s.mu.Lock()
		s.status = "closed"
		s.mu.Unlock()
		s.release()
		live.Delete(s.id)
	})
}

// Close implements session.Handle (TTL expiry, shutdown).
func (s *wsSession) Close() error {
	s.closeWith(int(websocket.StatusGoingAway), "session closed")
	return nil
}

func (s *wsSession) state() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]any{
		"state":       s.status,
		"subprotocol": s.hs.Subprotocol,
		"pending":     s.buf.Pending(),
		"sent":        s.sent.Load(),
		"received":    s.received.Load(),
	}
	if s.peerClose != nil {
		m["peer_close"] = s.peerClose
	}
	if s.readErr != "" {
		m["error"] = s.readErr
	}
	if n := s.pongs.Load() + s.pingFail.Load(); n > 0 {
		m["keepalive_pongs"] = s.pongs.Load()
		m["keepalive_failures"] = s.pingFail.Load()
	}
	return m
}

type wsConnectIn struct {
	wsTarget
	PingIntervalSeconds float64 `json:"ping_interval_seconds,omitempty" jsonschema:"send a keepalive ping this often (default off)"`
}

type wsConnectOut struct {
	SessionID      string             `json:"session_id"`
	URL            string             `json:"url"`
	Subprotocol    string             `json:"subprotocol,omitempty"`
	Handshake      *wsx.HandshakeInfo `json:"handshake"`
	BufferCapacity int                `json:"buffer_capacity"`
	Warnings       []string           `json:"warnings,omitempty"`
}

type wsSendIn struct {
	SessionID string `json:"session_id" jsonschema:"session handle from ws_connect"`
	types.Payload
	Type string `json:"type,omitempty" jsonschema:"frame type text or binary (default: text for text/json, binary for base64/file)"`
	Ping bool   `json:"ping,omitempty" jsonschema:"send a ping and wait for the pong instead of a data frame"`
}

type wsSendOut struct {
	SessionID string               `json:"session_id"`
	Sent      *types.StreamMessage `json:"sent,omitempty"`
	Ping      *pingResult          `json:"ping,omitempty"`
}

type pingResult struct {
	Pong  bool    `json:"pong"`
	RTTMS float64 `json:"rtt_ms"`
}

type wsCloseIn struct {
	SessionID string `json:"session_id" jsonschema:"session handle"`
	Code      int    `json:"code,omitempty" jsonschema:"close code to send (default 1000)"`
	Reason    string `json:"reason,omitempty" jsonschema:"close reason to send"`
}

type closeOut struct {
	SessionID string              `json:"session_id"`
	Closed    bool                `json:"closed"`
	CloseSent *types.CloseInfo    `json:"close_sent,omitempty"`
	PeerClose *types.CloseInfo    `json:"peer_close,omitempty"`
	Remaining *types.StreamResult `json:"remaining"`
}

type listIn struct {
	Kind string `json:"kind,omitempty" jsonschema:"ws, sio or empty for both"`
}

type listEntry struct {
	session.Info
	State map[string]any `json:"state,omitempty"`
}

type listOut struct {
	Sessions []listEntry `json:"sessions"`
}

func registerWSSession(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "ws_connect", "WebSocket connect",
		"Open an interactive WebSocket session and return a session_id. Incoming frames are buffered in the background "+
			"(bounded ring buffer; oldest dropped when full) until read with ws_receive. Supports headers, subprotocols, "+
			"Origin, auth, compression and keepalive pings (ping_interval_seconds). Close with ws_close.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in wsConnectIn) (any, error) {
			conn, hs, release, err := in.dial(ctx, d)
			if err != nil {
				return nil, err
			}
			rctx, cancel := context.WithCancel(context.Background())
			sess := &wsSession{
				conn: conn, release: release, buf: session.NewBuffer(d.Cfg.RingBufferSize), hs: hs,
				target: redact.URL(in.URL), cancel: cancel, done: make(chan struct{}), status: "open",
			}
			id, err := d.Sessions.Add(kindWS, sess.target, sess)
			if err != nil {
				cancel()
				conn.Close(websocket.StatusTryAgainLater, "session limit")
				release()
				return nil, err
			}
			sess.id = id
			live.Store(id, sess)
			go sess.reader(rctx)
			if in.PingIntervalSeconds > 0 {
				every := secs(in.PingIntervalSeconds)
				if every < 100*time.Millisecond {
					every = 100 * time.Millisecond
				}
				go sess.keepalive(rctx, every)
			}
			return wsConnectOut{SessionID: id, URL: hs.URL, Subprotocol: hs.Subprotocol, Handshake: hs,
				BufferCapacity: bufferCap(d), Warnings: in.warnings()}, nil
		})

	tools.Add(s, d, "ws_send", "WebSocket send",
		"Send one frame on a ws_connect session: text, json, base64 (binary) or a file streamed as one frame; "+
			"type overrides text/binary. Set ping=true to send a ping and measure the pong round trip.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in wsSendIn) (any, error) {
			sess, err := session.Get[*wsSession](d.Sessions, in.SessionID, kindWS)
			if err != nil {
				return nil, err
			}
			if err := in.Validate(); err != nil {
				return nil, err
			}
			sess.mu.Lock()
			status := sess.status
			sess.mu.Unlock()
			if status != "open" {
				return nil, fmt.Errorf("session %s is closed (read remaining messages with ws_receive, then ws_close)", in.SessionID)
			}
			sctx, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(0))
			defer cancel()
			if in.Ping {
				if !in.IsZero() {
					return nil, errors.New("ping cannot be combined with a payload")
				}
				start := time.Now()
				if err := sess.conn.Ping(sctx); err != nil {
					return nil, fmt.Errorf("ping: %w", err)
				}
				return wsSendOut{SessionID: in.SessionID, Ping: &pingResult{Pong: true, RTTMS: types.MS(time.Since(start))}}, nil
			}
			if in.IsZero() {
				return nil, errors.New("set one of text, json, base64 or file (or ping=true)")
			}
			typ, err := frameType(wsMessage{Payload: in.Payload, Type: in.Type})
			if err != nil {
				return nil, err
			}
			rec, err := sendFrame(sctx, d, sess.conn, in.Payload, typ)
			if err != nil {
				return nil, err
			}
			sess.sent.Add(1)
			rec.Seq = sess.buf.NextSeq()
			rec.TS = types.Now()
			return wsSendOut{SessionID: in.SessionID, Sent: &rec}, nil
		})

	tools.Add(s, d, "ws_receive", "WebSocket receive",
		"Drain buffered incoming frames from a ws_connect session (waits up to wait_seconds when empty). "+
			"ended_by is peer_closed (with the close code) once the server closed and the buffer is empty; dropped counts frames lost to buffer overflow.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in receiveIn) (any, error) {
			sess, err := session.Get[*wsSession](d.Sessions, in.SessionID, kindWS)
			if err != nil {
				return nil, err
			}
			res := sess.buf.Take(ctx, in.MaxMessages, in.wait(d))
			res.Meta = sess.state()
			return res, nil
		})

	tools.Add(s, d, "ws_close", "WebSocket close",
		"Close a ws_connect session with a close code and reason, and return any frames still buffered.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in wsCloseIn) (any, error) {
			code := in.Code
			if code == 0 {
				code = int(websocket.StatusNormalClosure)
			}
			if err := wsx.ValidateCloseCode(code); err != nil {
				return nil, err
			}
			if len(in.Reason) > 123 {
				return nil, errors.New("reason is limited to 123 bytes")
			}
			sess, err := session.Get[*wsSession](d.Sessions, in.SessionID, kindWS)
			if err != nil {
				return nil, err
			}
			d.Sessions.Remove(in.SessionID)
			sess.closeWith(code, in.Reason)
			sess.mu.Lock()
			out := closeOut{SessionID: in.SessionID, Closed: true, CloseSent: sess.sentClose, PeerClose: sess.peerClose}
			sess.mu.Unlock()
			out.Remaining = drain(ctx, sess.buf, d.Cfg.RingBufferSize)
			return out, nil
		})

	tools.Add(s, d, "ws_list", "List WebSocket/Socket.IO sessions",
		"List open ws and sio sessions with their state (open/closed, buffered messages, namespaces, transport).",
		tools.Local, func(ctx context.Context, req *mcp.CallToolRequest, in listIn) (any, error) {
			out := listOut{Sessions: []listEntry{}}
			for _, kind := range []string{kindWS, kindSIO} {
				if in.Kind != "" && in.Kind != kind {
					continue
				}
				for _, info := range d.Sessions.List(kind) {
					e := listEntry{Info: info}
					if h, ok := live.Load(info.ID); ok {
						e.State = h.(stater).state()
					}
					out.Sessions = append(out.Sessions, e)
				}
			}
			return out, nil
		})
}

func bufferCap(d *tools.Deps) int {
	if d.Cfg.RingBufferSize <= 0 {
		return 1000
	}
	return d.Cfg.RingBufferSize
}
