package apitools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type wsMsg struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type wsLog struct {
	mu       sync.Mutex
	got      []wsMsg
	header   http.Header
	finished chan struct{}
}

func (l *wsLog) add(m wsMsg) {
	l.mu.Lock()
	l.got = append(l.got, m)
	l.mu.Unlock()
}

func (l *wsLog) types() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, m := range l.got {
		out = append(out, m.Type)
	}
	return out
}

func (l *wsLog) find(typ string) *wsMsg {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.got {
		if m.Type == typ {
			m := m
			return &m
		}
	}
	return nil
}

// wsGraphQLServer implements graphql-transport-ws (and the legacy protocol
// when that subprotocol is chosen). Behaviour by operation:
//
//	count  - sends variables.n "next" events then "complete"
//	ticker - sends a "next" every 20ms until the client completes
//	fail   - sends an "error"
//	noack  - never acknowledges connection_init
func wsGraphQLServer(t *testing.T, subprotocols []string, log *wsLog) string {
	log.finished = make(chan struct{}, 16)
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		defer func() { log.finished <- struct{}{} }()
		log.mu.Lock()
		log.header = r.Header.Clone()
		log.mu.Unlock()
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: subprotocols})
		if err != nil {
			return
		}
		defer c.CloseNow()
		legacy := c.Subprotocol() == "graphql-ws"
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		var init wsMsg
		if err := wsjson.Read(ctx, c, &init); err != nil {
			return
		}
		log.add(init)
		if init.Type != "connection_init" {
			c.Close(4400, "expected connection_init")
			return
		}
		if strings.Contains(string(init.Payload), "noack") {
			// Wait for the client to give up.
			c.Read(ctx)
			return
		}
		wsjson.Write(ctx, c, wsMsg{Type: "connection_ack"})
		if !legacy {
			wsjson.Write(ctx, c, wsMsg{Type: "ping"})
		} else {
			wsjson.Write(ctx, c, wsMsg{Type: "ka"})
		}
		var sub wsMsg
		for {
			if err := wsjson.Read(ctx, c, &sub); err != nil {
				return
			}
			log.add(sub)
			if sub.Type == "subscribe" || sub.Type == "start" {
				break
			}
		}
		var p struct {
			Query     string
			Variables map[string]any
		}
		json.Unmarshal(sub.Payload, &p)
		next := "next"
		if legacy {
			next = "data"
		}
		// Reader for client messages (complete/stop/pong) after subscribe.
		clientDone := make(chan struct{})
		go func() {
			defer close(clientDone)
			for {
				var m wsMsg
				if err := wsjson.Read(ctx, c, &m); err != nil {
					return
				}
				log.add(m)
				if m.Type == "complete" || m.Type == "stop" || m.Type == "connection_terminate" {
					return
				}
			}
		}()
		switch {
		case strings.Contains(p.Query, "count"):
			n, _ := p.Variables["n"].(float64)
			for i := 1; i <= int(n); i++ {
				wsjson.Write(ctx, c, wsMsg{ID: sub.ID, Type: next, Payload: json.RawMessage(fmt.Sprintf(`{"data":{"count":%d}}`, i))})
			}
			wsjson.Write(ctx, c, wsMsg{ID: sub.ID, Type: "complete"})
		case strings.Contains(p.Query, "ticker"):
			for i := 1; ; i++ {
				if err := wsjson.Write(ctx, c, wsMsg{ID: sub.ID, Type: next, Payload: json.RawMessage(fmt.Sprintf(`{"data":{"tick":%d}}`, i))}); err != nil {
					return
				}
				select {
				case <-clientDone:
					c.Close(websocket.StatusNormalClosure, "")
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		case strings.Contains(p.Query, "fail"):
			wsjson.Write(ctx, c, wsMsg{ID: sub.ID, Type: "error", Payload: json.RawMessage(`[{"message":"no such field"}]`)})
		case strings.Contains(p.Query, "hangup"):
			wsjson.Write(ctx, c, wsMsg{ID: sub.ID, Type: next, Payload: json.RawMessage(`{"data":{"x":1}}`)})
			c.Close(4500, "server going away")
			return
		}
		select {
		case <-clientDone:
		case <-ctx.Done():
		}
		c.Close(websocket.StatusNormalClosure, "")
	})
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func waitFinished(t *testing.T, log *wsLog) {
	t.Helper()
	select {
	case <-log.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not finish")
	}
}

func TestGraphQLSubscribeTransportWS(t *testing.T) {
	h := newHarness(t)
	var log wsLog
	url := wsGraphQLServer(t, []string{"graphql-transport-ws"}, &log)
	r := stream(t, h, "graphql_subscribe", map[string]any{
		"url":               url,
		"query":             "subscription($n: Int!) { count(n: $n) }",
		"variables":         map[string]any{"n": 3},
		"connection_params": map[string]any{"authToken": "t0k"},
		"headers":           map[string]string{"X-Test": "yes"},
	})
	waitFinished(t, &log)
	if r.EndedBy != types.EndedComplete || len(r.Messages) != 4 {
		t.Fatalf("%+v", r)
	}
	for i := 0; i < 3; i++ {
		if m := r.Messages[i]; m.Event != "next" || m.Data != fmt.Sprintf(`{"data":{"count":%d}}`, i+1) || m.ID != "1" {
			t.Fatalf("msg %d %+v", i, m)
		}
	}
	if r.Messages[3].Event != "complete" {
		t.Fatalf("%+v", r.Messages[3])
	}
	if r.Meta["protocol"] != "graphql-transport-ws" || r.Meta["subprotocol"] != "graphql-transport-ws" ||
		r.Meta["acknowledged"] != true || r.Meta["handshake_status"] != float64(101) {
		t.Fatalf("meta %v", r.Meta)
	}
	init := log.find("connection_init")
	if init == nil || string(init.Payload) != `{"authToken":"t0k"}` {
		t.Fatalf("init %+v", init)
	}
	sub := log.find("subscribe")
	if sub == nil || !strings.Contains(string(sub.Payload), `"variables":{"n":3}`) {
		t.Fatalf("subscribe %+v", sub)
	}
	if log.find("pong") == nil {
		t.Fatalf("ping was not answered: %v", log.types())
	}
	log.mu.Lock()
	xt := log.header.Get("X-Test")
	log.mu.Unlock()
	if xt != "yes" {
		t.Fatalf("handshake header X-Test=%q", xt)
	}
	// The server completed: the client must not send its own complete.
	if log.find("complete") != nil {
		t.Fatalf("client sent complete after server complete: %v", log.types())
	}
}

func TestGraphQLSubscribeMaxMessagesSendsComplete(t *testing.T) {
	h := newHarness(t)
	var log wsLog
	url := wsGraphQLServer(t, []string{"graphql-transport-ws", "graphql-ws"}, &log)
	timed(t, 5*time.Second, func() {
		r := stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription { ticker }", "max_messages": 2})
		if r.EndedBy != types.EndedMaxMessages || len(r.Messages) != 2 {
			t.Fatalf("%+v", r)
		}
	})
	waitFinished(t, &log)
	if c := log.find("complete"); c == nil || c.ID != "1" {
		t.Fatalf("client did not complete the operation: %v", log.types())
	}
}

func TestGraphQLSubscribeLegacy(t *testing.T) {
	h := newHarness(t)
	var log wsLog
	// Server only speaks the legacy protocol; auto must pick it up.
	url := wsGraphQLServer(t, []string{"graphql-ws"}, &log)
	r := stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription($n: Int!) { count }", "variables": map[string]any{"n": 2}})
	waitFinished(t, &log)
	if r.EndedBy != types.EndedComplete || len(r.Messages) != 3 || r.Messages[0].Event != "next" {
		t.Fatalf("%+v", r)
	}
	if r.Meta["protocol"] != "subscriptions-transport-ws" || r.Meta["keepalives"] != float64(1) {
		t.Fatalf("meta %v", r.Meta)
	}
	if log.find("start") == nil {
		t.Fatalf("no start: %v", log.types())
	}

	// Legacy stop on limit.
	r = stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription { ticker }", "max_messages": 1, "protocol": "legacy"})
	waitFinished(t, &log)
	if r.EndedBy != types.EndedMaxMessages {
		t.Fatalf("%+v", r)
	}
	if log.find("stop") == nil {
		t.Fatalf("no stop: %v", log.types())
	}
}

func TestGraphQLSubscribeErrors(t *testing.T) {
	h := newHarness(t)
	var log wsLog
	url := wsGraphQLServer(t, []string{"graphql-transport-ws"}, &log)

	r := stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription { fail }"})
	if r.EndedBy != types.EndedError || len(r.Messages) != 1 || r.Messages[0].Event != "error" {
		t.Fatalf("%+v", r)
	}
	mustContain(t, r.Error, "no such field")
	waitFinished(t, &log)

	r = stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription { hangup }"})
	if r.EndedBy != types.EndedPeerClosed || len(r.Messages) != 1 || r.Close == nil || r.Close.Code != 4500 {
		t.Fatalf("%+v", r)
	}
	waitFinished(t, &log)

	timed(t, 5*time.Second, func() {
		r = stream(t, h, "graphql_subscribe", map[string]any{"url": url, "query": "subscription { x }",
			"connection_params": map[string]any{"mode": "noack"}, "ack_timeout_seconds": 0.3})
		if r.EndedBy != types.EndedError {
			t.Fatalf("%+v", r)
		}
		mustContain(t, r.Error, "connection_ack")
	})
	waitFinished(t, &log)

	// Handshake rejected by a plain HTTP endpoint.
	plain := server(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no websockets here", 404) })
	h.MustFail("graphql_subscribe", map[string]any{"url": plain.URL, "query": "subscription { x }"}, "HTTP 404")

	h.MustFail("graphql_subscribe", map[string]any{"url": url, "query": " "}, "query is required")
	h.MustFail("graphql_subscribe", map[string]any{"url": url, "query": "subscription { x }", "protocol": "graphql-ws"}, "ambiguous")
	h.MustFail("graphql_subscribe", map[string]any{"url": url, "query": "subscription { x }", "protocol": "mqtt"}, "unknown protocol")
}

func TestGraphQLSubscribeSSE(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var gotBody, gotAccept, gotCT string
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody, gotAccept, gotCT = string(b), r.Header.Get("Accept"), r.Header.Get("Content-Type")
		mu.Unlock()
		if r.Method != http.MethodPost {
			http.Error(w, "post only", 405)
			return
		}
		if strings.Contains(string(b), "denied") {
			writeJSON(w, map[string]any{"errors": []any{map[string]any{"message": "denied"}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		endless := strings.Contains(string(b), "ticker")
		for i := 1; i <= 3 || endless; i++ {
			if _, err := fmt.Fprintf(w, "event: next\ndata: {\"data\":{\"n\":%d}}\n\n", i); err != nil {
				return
			}
			fl.Flush()
			if endless {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
		io.WriteString(w, "event: complete\ndata:\n\n")
		fl.Flush()
	})
	r := stream(t, h, "graphql_subscribe", map[string]any{"url": srv.URL, "protocol": "sse", "query": "subscription { n }", "variables": map[string]any{"a": 1}})
	if r.EndedBy != types.EndedComplete || len(r.Messages) != 4 || r.Messages[0].Event != "next" || r.Messages[2].Data != `{"data":{"n":3}}` {
		t.Fatalf("%+v", r)
	}
	if r.Meta["protocol"] != "sse" || r.Meta["status"] != float64(200) {
		t.Fatalf("meta %v", r.Meta)
	}
	mu.Lock()
	if gotAccept != "text/event-stream" || gotCT != "application/json" || !strings.Contains(gotBody, `"variables":{"a":1}`) {
		t.Fatalf("request accept=%q ct=%q body=%s", gotAccept, gotCT, gotBody)
	}
	mu.Unlock()

	timed(t, 5*time.Second, func() {
		r = stream(t, h, "graphql_subscribe", map[string]any{"url": srv.URL, "protocol": "sse", "query": "subscription { ticker }", "max_messages": 2})
		if r.EndedBy != types.EndedMaxMessages || len(r.Messages) != 2 {
			t.Fatalf("%+v", r)
		}
	})

	r = stream(t, h, "graphql_subscribe", map[string]any{"url": srv.URL, "protocol": "sse", "query": "subscription { denied }"})
	if r.EndedBy != types.EndedError || len(r.Messages) != 1 || !strings.Contains(r.Messages[0].Data, "denied") {
		t.Fatalf("%+v", r)
	}
}

// timeout_seconds bounds connecting, not the stream: a stream longer than
// the request timeout runs until its own limit.
func TestStreamsOutliveRequestTimeout(t *testing.T) {
	h := newHarness(t)
	var log wsLog
	ws := wsGraphQLServer(t, []string{"graphql-transport-ws"}, &log)
	var seen sseSeen
	sseURL := sseServer(t, &seen)

	timed(t, 5*time.Second, func() {
		r := stream(t, h, "graphql_subscribe", map[string]any{"url": ws, "query": "subscription { ticker }",
			"timeout_seconds": 0.3, "max_duration_seconds": 1.2})
		if r.EndedBy != types.EndedMaxDuration || len(r.Messages) < 20 {
			t.Fatalf("ws: ended_by %s after %d messages (%s)", r.EndedBy, len(r.Messages), r.Error)
		}
	})
	waitFinished(t, &log)
	timed(t, 5*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{"url": sseURL + "/endless",
			"timeout_seconds": 0.3, "max_duration_seconds": 1.2})
		if r.EndedBy != types.EndedMaxDuration || len(r.Messages) < 20 {
			t.Fatalf("sse: ended_by %s after %d messages (%s)", r.EndedBy, len(r.Messages), r.Error)
		}
	})
}
