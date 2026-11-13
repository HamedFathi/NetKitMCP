package wstools

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
	"github.com/HamedFathi/NetKitMCP/internal/wsx"
)

// wsTarget are the options identifying a WebSocket endpoint.
type wsTarget struct {
	URL          string   `json:"url" jsonschema:"WebSocket URL (ws:// or wss://; http/https are converted)"`
	Subprotocols []string `json:"subprotocols,omitempty" jsonschema:"subprotocols to offer (Sec-WebSocket-Protocol); the negotiated one is reported"`
	connOptions
}

// wsMessage is one outgoing frame.
type wsMessage struct {
	types.Payload
	Type    string `json:"type,omitempty" jsonschema:"frame type text or binary (default: text for text/json, binary for base64/file)"`
	DelayMS int    `json:"delay_ms,omitempty" jsonschema:"wait this many milliseconds before sending"`
}

type wsExchangeIn struct {
	wsTarget
	Messages []wsMessage `json:"messages,omitempty" jsonschema:"frames to send in order after connecting"`
	types.StreamLimits
	StopOn      string `json:"stop_on,omitempty" jsonschema:"stop collecting when an incoming message contains this substring"`
	StopOnRegex bool   `json:"stop_on_regex,omitempty" jsonschema:"treat stop_on as a regular expression"`
	CloseCode   int    `json:"close_code,omitempty" jsonschema:"close code to send at the end (default 1000)"`
	CloseReason string `json:"close_reason,omitempty" jsonschema:"close reason to send at the end"`
}

func (t wsTarget) dial(ctx context.Context, d *tools.Deps) (*websocket.Conn, *wsx.HandshakeInfo, func(), error) {
	if _, err := wsx.NormalizeURL(t.URL); err != nil {
		return nil, nil, nil, err
	}
	c, err := newClient(d, t.connOptions, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	conn, hs, err := wsx.Dial(dctx, wsx.Options{
		URL:          t.URL,
		HTTPClient:   c.Client,
		Header:       tools.Headers(t.Headers),
		Origin:       t.Origin,
		Subprotocols: t.Subprotocols,
		Compression:  t.Compression,
		ReadLimit:    d.Cfg.ResponseBytes(t.MaxMessageBytes),
	})
	if err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	return conn, hs, c.Close, nil
}

// frameType decides the frame type for a message.
func frameType(m wsMessage) (websocket.MessageType, error) {
	if m.Type != "" {
		return wsx.MessageType(m.Type)
	}
	if m.Base64 != "" || m.File != "" {
		return websocket.MessageBinary, nil
	}
	return websocket.MessageText, nil
}

func validateMessages(d *tools.Deps, msgs []wsMessage) error {
	for i, m := range msgs {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("messages[%d]: %w", i, err)
		}
		if m.IsZero() {
			return fmt.Errorf("messages[%d]: set one of text, json, base64 or file", i)
		}
		if _, err := frameType(m); err != nil {
			return fmt.Errorf("messages[%d]: %w", i, err)
		}
		if m.File != "" {
			if _, err := d.Files.ResolveRead(m.File); err != nil {
				return fmt.Errorf("messages[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// sendFrame resolves and sends one message, streaming file payloads.
func sendFrame(ctx context.Context, d *tools.Deps, conn *websocket.Conn, p types.Payload, typ websocket.MessageType) (types.StreamMessage, error) {
	rp, err := p.Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, d.Cfg.UploadBytes(0))
	if err != nil {
		return types.StreamMessage{}, err
	}
	defer rp.Close()
	if rp.Reader != nil {
		w, err := conn.Writer(ctx, typ)
		if err != nil {
			return types.StreamMessage{}, err
		}
		hr := fileio.NewHashingReader(rp.Reader)
		if _, err := io.Copy(w, hr); err != nil {
			w.Close()
			return types.StreamMessage{}, fmt.Errorf("streaming file: %w", err)
		}
		if err := w.Close(); err != nil {
			return types.StreamMessage{}, err
		}
		fi := *rp.File
		fi.SHA256 = hr.SHA256()
		fi.SizeBytes = hr.N()
		return types.StreamMessage{Dir: "out", Type: wsx.TypeName(typ), Data: "", Encoding: "none",
			Meta: map[string]any{"size_bytes": hr.N(), "file": fi}}, nil
	}
	if err := conn.Write(ctx, typ, rp.Data); err != nil {
		return types.StreamMessage{}, err
	}
	return wsx.Message("out", typ, rp.Data), nil
}

// closeConn performs the close handshake with a bound on how long it may take.
func closeConn(conn *websocket.Conn, code int, reason string) {
	done := make(chan struct{})
	go func() {
		conn.Close(websocket.StatusCode(code), reason)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		conn.CloseNow()
	}
}

func registerWS(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "ws_exchange", "WebSocket exchange",
		"One-shot WebSocket call: connect (custom headers, subprotocols, Origin, auth), send messages[] in order "+
			"(text, json, base64 binary or a file streamed as one frame; optional delay_ms), collect incoming frames until "+
			"max_messages, max_duration_seconds, idle_timeout_seconds or stop_on, then close with close_code/close_reason. "+
			"Returns all frames in order (dir in/out; binary as base64), the close code/reason and the handshake (negotiated subprotocol, response headers). "+
			"Use ws_connect for interactive sessions.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in wsExchangeIn) (any, error) {
			return wsExchange(ctx, d, in)
		})
}

func wsExchange(ctx context.Context, d *tools.Deps, in wsExchangeIn) (any, error) {
	if err := validateMessages(d, in.Messages); err != nil {
		return nil, err
	}
	code := in.CloseCode
	if code == 0 {
		code = int(websocket.StatusNormalClosure)
	}
	if err := wsx.ValidateCloseCode(code); err != nil {
		return nil, err
	}
	if len(in.CloseReason) > 123 {
		return nil, fmt.Errorf("close_reason is limited to 123 bytes")
	}
	stop, err := matcher(in.StopOn, in.StopOnRegex)
	if err != nil {
		return nil, err
	}
	conn, hs, release, err := in.dial(ctx, d)
	if err != nil {
		return nil, err
	}
	defer release()
	defer conn.CloseNow()

	col := types.NewCollector(d.Cfg.Messages(in.MaxMessages), d.Cfg.StreamDuration(in.MaxDurationSeconds), secs(in.IdleTimeoutSeconds), 0)
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	var peerClose atomic.Pointer[types.CloseInfo]
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			typ, data, err := conn.Read(runCtx)
			if err != nil {
				if ci := wsx.CloseInfo(err); ci != nil {
					peerClose.Store(ci)
					col.SetClose(ci.Code, ci.Reason)
					col.Finish(types.EndedPeerClosed, nil)
				} else if runCtx.Err() == nil {
					col.Finish(types.EndedError, err)
				}
				return
			}
			if !col.Add(wsx.Message("in", typ, data)) {
				continue
			}
			if stop != nil && stop(string(data)) {
				col.Finish(types.EndedStopEvent, nil)
			}
		}
	}()

	go func() {
		for i, m := range in.Messages {
			if !sleepCtx(runCtx, col.Done(), time.Duration(m.DelayMS)*time.Millisecond) {
				return
			}
			select {
			case <-col.Done():
				return
			default:
			}
			typ, _ := frameType(m)
			rec, err := sendFrame(runCtx, d, conn, m.Payload, typ)
			if err != nil {
				col.Finish(types.EndedError, fmt.Errorf("sending messages[%d]: %w", i, err))
				return
			}
			col.Add(rec)
		}
	}()

	res := col.Wait(ctx)
	initiator := "server"
	pc := peerClose.Load()
	if pc == nil {
		initiator = "client"
		closeConn(conn, code, in.CloseReason)
	}
	runCancel()
	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
	}
	if res.Close == nil {
		if pc != nil {
			res.Close = pc
		} else {
			res.Close = &types.CloseInfo{Code: code, Reason: in.CloseReason}
		}
	}
	res.Meta = map[string]any{"handshake": hs, "close_initiator": initiator}
	if w := in.warnings(); w != nil {
		res.Meta["warnings"] = w
	}
	return res, nil
}
