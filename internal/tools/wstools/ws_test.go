package wstools_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/wstools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// seen records what the WebSocket test server observed.
type seen struct {
	mu        sync.Mutex
	headers   http.Header
	closeCode int
	closeText string
	closed    chan struct{}
}

func (s *seen) header(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers.Get(k)
}

func (s *seen) waitClose(t *testing.T) (int, string) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe a close")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCode, s.closeText
}

// wsServer echoes frames and understands a few text commands:
// "close:CODE:REASON", "flood:N" (sends m0..mN-1) and "headers".
func wsServer(t *testing.T) (string, *seen) {
	t.Helper()
	sn := &seen{closed: make(chan struct{}, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "go away", http.StatusForbidden)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		sn.mu.Lock()
		sn.headers = r.Header.Clone()
		sn.mu.Unlock()
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:       []string{"chat.v2", "chat.v1"},
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		c.SetReadLimit(16 << 20)
		ctx := r.Context()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				var ce websocket.CloseError
				sn.mu.Lock()
				if errors.As(err, &ce) {
					sn.closeCode, sn.closeText = int(ce.Code), ce.Reason
				} else {
					sn.closeCode, sn.closeText = -1, err.Error()
				}
				sn.mu.Unlock()
				sn.closed <- struct{}{}
				return
			}
			if typ == websocket.MessageText {
				s := string(data)
				switch {
				case strings.HasPrefix(s, "close:"):
					parts := strings.SplitN(s, ":", 3)
					code, _ := strconv.Atoi(parts[1])
					c.Close(websocket.StatusCode(code), parts[2])
					sn.closed <- struct{}{}
					return
				case strings.HasPrefix(s, "flood:"):
					n, _ := strconv.Atoi(strings.TrimPrefix(s, "flood:"))
					for i := 0; i < n; i++ {
						c.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf("m%d", i)))
					}
					continue
				case s == "headers":
					sn.mu.Lock()
					b, _ := json.Marshal(map[string]string{
						"origin": sn.headers.Get("Origin"), "authorization": sn.headers.Get("Authorization"),
						"x_custom": sn.headers.Get("X-Custom"),
					})
					sn.mu.Unlock()
					c.Write(ctx, websocket.MessageText, b)
					continue
				}
			}
			if err := c.Write(ctx, typ, data); err != nil {
				return
			}
		}
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http"), sn
}

func msgs(t *testing.T, r *tooltest.Result) types.StreamResult {
	t.Helper()
	var sr types.StreamResult
	r.Decode(t, &sr)
	return sr
}

func filterDir(ms []types.StreamMessage, dir string) []types.StreamMessage {
	var out []types.StreamMessage
	for _, m := range ms {
		if m.Dir == dir {
			out = append(out, m)
		}
	}
	return out
}

func TestToolsRegistered(t *testing.T) {
	h := tooltest.New(t, "ws")
	names := strings.Join(h.ListTools(), ",")
	for _, n := range []string{"ws_exchange", "ws_connect", "ws_send", "ws_receive", "ws_close", "ws_list",
		"sio_exchange", "sio_connect", "sio_emit", "sio_receive", "sio_close"} {
		if !strings.Contains(","+names+",", ","+n+",") {
			t.Errorf("tool %s not registered (have %s)", n, names)
		}
	}
}

func TestWSExchangePayloads(t *testing.T) {
	url, sn := wsServer(t)
	h := tooltest.New(t, "ws")
	fileData := make([]byte, 100000)
	for i := range fileData {
		fileData[i] = byte(i)
	}
	sum := sha256.Sum256(fileData)
	path := h.WriteInput("blob.bin", fileData)

	r := h.MustOK("ws_exchange", map[string]any{
		"url":          url + "/ws",
		"subprotocols": []string{"chat.v1", "chat.v2"},
		"origin":       "https://app.example",
		"headers":      map[string]string{"X-Custom": "c1"},
		"auth":         map[string]any{"type": "bearer", "token": "tok123"},
		"messages": []map[string]any{
			{"text": "hello"},
			{"json": map[string]any{"a": 1}, "delay_ms": 10},
			{"base64": "AAEC"},
			{"file": path},
			{"text": "headers"},
		},
		"max_messages": 5,
	})
	sr := msgs(t, r)
	if sr.EndedBy != types.EndedMaxMessages {
		t.Fatalf("ended_by = %s (%s)", sr.EndedBy, sr.Error)
	}
	in := filterDir(sr.Messages, "in")
	out := filterDir(sr.Messages, "out")
	if len(in) != 5 || len(out) != 5 {
		t.Fatalf("in=%d out=%d: %+v", len(in), len(out), sr.Messages)
	}
	if in[0].Data != "hello" || in[0].Type != "text" {
		t.Errorf("in[0] = %+v", in[0])
	}
	if in[1].Data != `{"a":1}` || in[1].Type != "text" {
		t.Errorf("in[1] = %+v", in[1])
	}
	if in[2].Data != "AAEC" || in[2].Type != "binary" || in[2].Encoding != "base64" {
		t.Errorf("in[2] = %+v", in[2])
	}
	got, _ := base64.StdEncoding.DecodeString(in[3].Data)
	if in[3].Type != "binary" || sha256.Sum256(got) != sum {
		t.Errorf("file echo mismatch (%d bytes)", len(got))
	}
	var hdrs map[string]string
	json.Unmarshal([]byte(in[4].Data), &hdrs)
	if hdrs["origin"] != "https://app.example" || hdrs["authorization"] != "Bearer tok123" || hdrs["x_custom"] != "c1" {
		t.Errorf("server saw headers %v", hdrs)
	}
	fileMeta, _ := out[3].Meta["file"].(map[string]any)
	if fileMeta["sha256"] != hex.EncodeToString(sum[:]) || fileMeta["size_bytes"] != float64(len(fileData)) {
		t.Errorf("file meta = %v", out[3].Meta)
	}
	hs := sr.Meta["handshake"].(map[string]any)
	if hs["subprotocol"] != "chat.v2" || hs["status"] != float64(101) {
		t.Errorf("handshake = %v", hs)
	}
	if _, ok := hs["headers"].(map[string]any)["Sec-Websocket-Accept"]; !ok {
		t.Errorf("handshake headers = %v", hs["headers"])
	}
	if sr.Close == nil || sr.Close.Code != 1000 || sr.Meta["close_initiator"] != "client" {
		t.Errorf("close = %+v meta=%v", sr.Close, sr.Meta)
	}
	if code, _ := sn.waitClose(t); code != 1000 {
		t.Errorf("server saw close code %d", code)
	}
}

func TestWSExchangeCloseCodes(t *testing.T) {
	url, sn := wsServer(t)
	h := tooltest.New(t, "ws")

	// Server-initiated close.
	r := h.MustOK("ws_exchange", map[string]any{
		"url": strings.Replace(url, "ws://", "http://", 1) + "/ws", "messages": []map[string]any{{"text": "close:4001:bye now"}},
	})
	sr := msgs(t, r)
	if sr.EndedBy != types.EndedPeerClosed || sr.Close == nil || sr.Close.Code != 4001 || sr.Close.Reason != "bye now" || sr.Meta["close_initiator"] != "server" {
		t.Fatalf("result = %+v", sr)
	}
	sn.waitClose(t)

	// Client-chosen close code/reason.
	r = h.MustOK("ws_exchange", map[string]any{
		"url": url + "/ws", "messages": []map[string]any{{"text": "x"}}, "max_messages": 1,
		"close_code": 4000, "close_reason": "done here",
	})
	sr = msgs(t, r)
	if sr.Close == nil || sr.Close.Code != 4000 {
		t.Fatalf("close = %+v", sr.Close)
	}
	if code, reason := sn.waitClose(t); code != 4000 || reason != "done here" {
		t.Fatalf("server saw %d %q", code, reason)
	}

	h.MustFail("ws_exchange", map[string]any{"url": url + "/ws", "close_code": 1005}, "close_code")
}

func TestWSExchangeStopAndIdle(t *testing.T) {
	url, _ := wsServer(t)
	h := tooltest.New(t, "ws")
	r := h.MustOK("ws_exchange", map[string]any{
		"url": url + "/ws", "messages": []map[string]any{{"text": "flood:10"}}, "stop_on": "m3",
	})
	sr := msgs(t, r)
	in := filterDir(sr.Messages, "in")
	if sr.EndedBy != types.EndedStopEvent || in[len(in)-1].Data != "m3" {
		t.Fatalf("stop_on result = %+v", sr)
	}
	r = h.MustOK("ws_exchange", map[string]any{
		"url": url + "/ws", "messages": []map[string]any{{"text": "flood:10"}}, "stop_on": `^m[5]$`, "stop_on_regex": true,
	})
	sr = msgs(t, r)
	in = filterDir(sr.Messages, "in")
	if sr.EndedBy != types.EndedStopEvent || in[len(in)-1].Data != "m5" {
		t.Fatalf("regex stop result = %+v", sr)
	}
	start := time.Now()
	r = h.MustOK("ws_exchange", map[string]any{
		"url": url + "/ws", "messages": []map[string]any{{"text": "flood:2"}}, "idle_timeout_seconds": 0.3,
	})
	sr = msgs(t, r)
	if sr.EndedBy != types.EndedIdle || len(filterDir(sr.Messages, "in")) != 2 || time.Since(start) > 4*time.Second {
		t.Fatalf("idle result = %+v", sr)
	}
	r = h.MustOK("ws_exchange", map[string]any{"url": url + "/ws", "max_duration_seconds": 0.2})
	if sr = msgs(t, r); sr.EndedBy != types.EndedMaxDuration {
		t.Fatalf("duration result = %+v", sr)
	}
}

func TestWSExchangeErrors(t *testing.T) {
	url, _ := wsServer(t)
	h := tooltest.New(t, "ws")
	h.MustFail("ws_exchange", map[string]any{"url": url + "/forbidden"}, "403")
	h.MustFail("ws_exchange", map[string]any{"url": "ftp://example.com/"}, "scheme")
	h.MustFail("ws_exchange", map[string]any{"url": url + "/ws", "messages": []map[string]any{{"text": "a", "base64": "AA=="}}}, "only one")
	h.MustFail("ws_exchange", map[string]any{"url": url + "/ws", "messages": []map[string]any{{}}}, "set one of")
	h.MustFail("ws_exchange", map[string]any{"url": url + "/ws", "messages": []map[string]any{{"file": "/etc/passwd"}}, "max_messages": 1}, "")
	// Unsupported subprotocol offered alone is still accepted without one.
	r := h.MustOK("ws_exchange", map[string]any{"url": url + "/ws", "subprotocols": []string{"nope"}, "max_duration_seconds": 0.1})
	sr := msgs(t, r)
	if hs := sr.Meta["handshake"].(map[string]any); hs["subprotocol"] != nil {
		t.Fatalf("unexpected subprotocol %v", hs["subprotocol"])
	}
}

func TestWSSSRFGuard(t *testing.T) {
	url, _ := wsServer(t)
	h := tooltest.New(t, "ws", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("ws_exchange", map[string]any{"url": url + "/ws"}, "allow_private")
	h.MustFail("ws_connect", map[string]any{"url": url + "/ws"}, "allow_private")
	h.MustFail("ws_exchange", map[string]any{"url": strings.Replace(url, "127.0.0.1", "localhost", 1) + "/ws"}, "allow_private")
	r := h.MustOK("ws_exchange", map[string]any{"url": url + "/ws", "allow_private": true,
		"messages": []map[string]any{{"text": "ok"}}, "max_messages": 1})
	if sr := msgs(t, r); len(filterDir(sr.Messages, "in")) != 1 {
		t.Fatalf("result = %+v", sr)
	}
}

func TestWSSession(t *testing.T) {
	url, sn := wsServer(t)
	h := tooltest.New(t, "ws")
	h.Deps.Cfg.RingBufferSize = 5

	r := h.MustOK("ws_connect", map[string]any{
		"url": url + "/ws", "subprotocols": []string{"chat.v1"}, "origin": "https://o.example",
		"auth": map[string]any{"type": "bearer", "token": "sess-token"}, "ping_interval_seconds": 0.1,
	})
	id, _ := r.Data["session_id"].(string)
	if id == "" || r.Data["subprotocol"] != "chat.v1" || r.Data["buffer_capacity"] != float64(5) {
		t.Fatalf("connect = %v", r.Data)
	}
	if sn.header("Authorization") != "Bearer sess-token" || sn.header("Origin") != "https://o.example" {
		t.Fatalf("server headers = %v", sn.headers)
	}

	r = h.MustOK("ws_send", map[string]any{"session_id": id, "text": "one"})
	if sent := r.Data["sent"].(map[string]any); sent["dir"] != "out" || sent["data"] != "one" {
		t.Fatalf("sent = %v", sent)
	}
	h.MustOK("ws_send", map[string]any{"session_id": id, "base64": "AQID"})
	h.MustOK("ws_send", map[string]any{"session_id": id, "json": []int{1, 2}, "type": "binary"})
	path := h.WriteInput("f.txt", []byte("file-content"))
	h.MustOK("ws_send", map[string]any{"session_id": id, "file": path, "type": "text"})
	r = h.MustOK("ws_send", map[string]any{"session_id": id, "ping": true})
	if p := r.Data["ping"].(map[string]any); p["pong"] != true {
		t.Fatalf("ping = %v", p)
	}
	h.MustFail("ws_send", map[string]any{"session_id": id}, "set one of")
	h.MustFail("ws_send", map[string]any{"session_id": id, "ping": true, "text": "x"}, "ping cannot")

	var got []types.StreamMessage
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < 4 && time.Now().Before(deadline) {
		sr := msgs(t, h.MustOK("ws_receive", map[string]any{"session_id": id, "wait_seconds": 1}))
		got = append(got, sr.Messages...)
	}
	if len(got) != 4 || got[0].Data != "one" || got[1].Data != "AQID" || got[2].Type != "binary" ||
		got[2].Data != base64.StdEncoding.EncodeToString([]byte("[1,2]")) || got[3].Data != "file-content" {
		t.Fatalf("received = %+v", got)
	}

	// Ring buffer overflow.
	h.MustOK("ws_send", map[string]any{"session_id": id, "text": "flood:20"})
	waitPending(t, h, id, 5)
	time.Sleep(100 * time.Millisecond)
	sr := msgs(t, h.MustOK("ws_receive", map[string]any{"session_id": id, "max_messages": 50}))
	if sr.Dropped != 15 || len(sr.Messages) != 5 || sr.Messages[0].Data != "m15" {
		t.Fatalf("overflow receive = dropped %d, %+v", sr.Dropped, sr.Messages)
	}

	// ws_list shows state including keepalive pongs.
	time.Sleep(250 * time.Millisecond)
	l := h.MustOK("ws_list", map[string]any{})
	sessions := l.Data["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("list = %v", l.Data)
	}
	st := sessions[0].(map[string]any)["state"].(map[string]any)
	if st["state"] != "open" || st["keepalive_pongs"].(float64) < 1 || sessions[0].(map[string]any)["kind"] != "ws" {
		t.Fatalf("state = %v", st)
	}

	// Peer close is recorded.
	h.MustOK("ws_send", map[string]any{"session_id": id, "text": "close:4002:later"})
	sr = msgs(t, h.MustOK("ws_receive", map[string]any{"session_id": id, "wait_seconds": 3}))
	if sr.EndedBy != types.EndedPeerClosed || sr.Close == nil || sr.Close.Code != 4002 || sr.Close.Reason != "later" {
		t.Fatalf("peer close = %+v", sr)
	}
	h.MustFail("ws_send", map[string]any{"session_id": id, "text": "x"}, "closed")
	r = h.MustOK("ws_close", map[string]any{"session_id": id})
	if r.Data["closed"] != true || r.Data["peer_close"].(map[string]any)["code"] != float64(4002) {
		t.Fatalf("close = %v", r.Data)
	}
	h.MustFail("ws_receive", map[string]any{"session_id": id}, "not found")
	sn.waitClose(t)

	// Client close with a code.
	r = h.MustOK("ws_connect", map[string]any{"url": url + "/ws"})
	id2 := r.Data["session_id"].(string)
	h.MustOK("ws_send", map[string]any{"session_id": id2, "text": "pending"})
	time.Sleep(100 * time.Millisecond)
	r = h.MustOK("ws_close", map[string]any{"session_id": id2, "code": 4003, "reason": "bye"})
	if r.Data["close_sent"].(map[string]any)["code"] != float64(4003) {
		t.Fatalf("close = %v", r.Data)
	}
	if rem := r.Data["remaining"].(map[string]any)["messages"].([]any); len(rem) != 1 {
		t.Fatalf("remaining = %v", rem)
	}
	if code, reason := sn.waitClose(t); code != 4003 || reason != "bye" {
		t.Fatalf("server saw %d %q", code, reason)
	}
	if l := h.MustOK("ws_list", map[string]any{}); len(l.Data["sessions"].([]any)) != 0 {
		t.Fatalf("list after close = %v", l.Data)
	}
	h.MustFail("ws_close", map[string]any{"session_id": id2}, "not found")
}

func waitPending(t *testing.T, h *tooltest.Harness, id string, n float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l := h.MustOK("ws_list", map[string]any{})
		for _, s := range l.Data["sessions"].([]any) {
			m := s.(map[string]any)
			if m["session_id"] == id && m["state"].(map[string]any)["pending"] == n {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %s never reached %v pending messages", id, n)
}

func TestWSSessionCloseAll(t *testing.T) {
	url, sn := wsServer(t)
	h := tooltest.New(t, "ws")
	r := h.MustOK("ws_connect", map[string]any{"url": url + "/ws"})
	id := r.Data["session_id"].(string)
	// CloseAll (shutdown / TTL expiry path) closes the connection.
	h.Deps.Sessions.CloseAll()
	if code, _ := sn.waitClose(t); code != 1001 {
		t.Fatalf("server saw close code %d", code)
	}
	h.MustFail("ws_send", map[string]any{"session_id": id, "text": "x"}, "not found")
}
