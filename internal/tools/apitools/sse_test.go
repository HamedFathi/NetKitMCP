package apitools_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// sseReq is what the SSE test server saw in the last request.
type sseReq struct {
	method      string
	body        string
	contentType string
	lastEventID string
	accept      string
}

type sseSeen struct {
	mu  sync.Mutex
	req sseReq
}

func (s *sseSeen) get() sseReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.req
}

// sseServer streams events according to the path:
//
//	/finite  - three events (one multi-line, one named, a comment, a retry), then closes
//	/endless - an event every 20ms until the client goes away
//	/done    - two chunks then "[DONE]" then keeps the connection open
//	/stall   - one event, then silence until the client goes away
//	/burst   - ten events with ids written at once, then silence
//	/json    - a JSON error body (not an event stream)
func sseServer(t *testing.T, seen *sseSeen) string {
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.req = sseReq{method: r.Method, body: string(b), contentType: r.Header.Get("Content-Type"),
			lastEventID: r.Header.Get("Last-Event-ID"), accept: r.Header.Get("Accept")}
		seen.mu.Unlock()
		if r.URL.Path == "/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		send := func(s string) bool {
			if _, err := io.WriteString(w, s); err != nil {
				return false
			}
			fl.Flush()
			return true
		}
		switch r.URL.Path {
		case "/finite":
			send(": hello comment\nretry: 1500\nid: 1\ndata: line one\ndata: line two\n\n")
			send("event: update\nid: 2\ndata: {\"n\":2}\n\n")
			send("data: no id change\n\n")
			send("data: incomplete trailing event is dropped")
		case "/endless":
			for i := 1; ; i++ {
				if !send(fmt.Sprintf("id: %d\ndata: tick %d\n\n", i, i)) {
					return
				}
				select {
				case <-r.Context().Done():
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		case "/done":
			send("data: {\"delta\":\"Hel\"}\n\n")
			send("data: {\"delta\":\"lo\"}\n\n")
			send("data: [DONE]\n\n")
			send("data: after done\n\n")
			<-r.Context().Done()
		case "/stall":
			send("event: first\ndata: only\n\n")
			<-r.Context().Done()
		case "/burst":
			var sb strings.Builder
			for i := 1; i <= 10; i++ {
				fmt.Fprintf(&sb, "id: e%d\ndata: %d\n\n", i, i)
			}
			send(sb.String())
			<-r.Context().Done()
		}
	})
	return srv.URL
}

func TestSSEPeerClose(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	r := stream(t, h, "sse_listen", map[string]any{"url": url + "/finite"})
	if r.EndedBy != types.EndedPeerClosed || len(r.Messages) != 3 {
		t.Fatalf("%+v", r)
	}
	m := r.Messages
	if m[0].Event != "message" || m[0].ID != "1" || m[0].Data != "line one\nline two" || m[0].Meta["retry_ms"] != float64(1500) {
		t.Fatalf("msg0 %+v", m[0])
	}
	if m[1].Event != "update" || m[1].ID != "2" || m[1].Data != `{"n":2}` {
		t.Fatalf("msg1 %+v", m[1])
	}
	if m[2].ID != "2" || m[2].Data != "no id change" {
		t.Fatalf("msg2 %+v", m[2])
	}
	if r.Meta["status"] != float64(200) || r.Meta["last_event_id"] != "2" || r.Meta["comments"] != float64(1) {
		t.Fatalf("meta %v", r.Meta)
	}
	if s := seen.get(); s.method != "GET" || s.accept != "text/event-stream" || s.lastEventID != "" {
		t.Fatalf("seen %+v", s)
	}
}

func TestSSEMaxMessagesAndLastEventID(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	timed(t, 5*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{"url": url + "/endless", "max_messages": 3, "last_event_id": "41"})
		if r.EndedBy != types.EndedMaxMessages || len(r.Messages) != 3 || r.Messages[2].Data != "tick 3" {
			t.Fatalf("%+v", r)
		}
		if r.Meta["last_event_id"] != "3" {
			t.Fatalf("meta %v", r.Meta)
		}
	})
	if s := seen.get(); s.lastEventID != "41" {
		t.Fatalf("Last-Event-ID %q", s.lastEventID)
	}
}

// When several events arrive in one chunk, last_event_id must be the id of
// the last event returned, not of an event parsed after the limit hit.
func TestSSEBurstLastEventID(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	for i := 0; i < 5; i++ {
		r := stream(t, h, "sse_listen", map[string]any{"url": url + "/burst", "max_messages": 2})
		if r.EndedBy != types.EndedMaxMessages || len(r.Messages) != 2 {
			t.Fatalf("%+v", r)
		}
		if r.Meta["last_event_id"] != "e2" {
			t.Fatalf("last_event_id %v after messages %+v", r.Meta["last_event_id"], r.Messages)
		}
	}
}

func TestSSEStopDataPOST(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	timed(t, 4*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{
			"url": url + "/done", "body": map[string]any{"json": map[string]any{"stream": true}},
			"stop_data": "[DONE]",
		})
		if r.EndedBy != types.EndedStopEvent || len(r.Messages) != 3 || r.Messages[2].Data != "[DONE]" {
			t.Fatalf("%+v", r)
		}
	})
	s := seen.get()
	if s.method != "POST" || s.body != `{"stream":true}` || s.contentType != "application/json" {
		t.Fatalf("seen %+v", s)
	}

	r := stream(t, h, "sse_listen", map[string]any{"url": url + "/finite", "stop_event": "update"})
	if r.EndedBy != types.EndedStopEvent || len(r.Messages) != 2 {
		t.Fatalf("%+v", r)
	}

	// Text body with an explicit content type.
	stream(t, h, "sse_listen", map[string]any{"url": url + "/finite", "method": "POST",
		"body": map[string]any{"text": "q=1"}, "content_type": "application/x-www-form-urlencoded"})
	if s := seen.get(); s.body != "q=1" || s.contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("seen %+v", s)
	}
}

func TestSSEIdleAndDuration(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	d := timed(t, 3*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{"url": url + "/stall", "idle_timeout_seconds": 0.3})
		if r.EndedBy != types.EndedIdle || len(r.Messages) != 1 {
			t.Fatalf("%+v", r)
		}
	})
	if d < 250*time.Millisecond {
		t.Fatalf("idle ended too early: %s", d)
	}
	timed(t, 3*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{"url": url + "/stall", "max_duration_seconds": 0.4})
		if r.EndedBy != types.EndedMaxDuration || len(r.Messages) != 1 {
			t.Fatalf("%+v", r)
		}
	})
	// The default stream duration (5s in the harness) bounds an endless stream.
	timed(t, 8*time.Second, func() {
		r := stream(t, h, "sse_listen", map[string]any{"url": url + "/stall"})
		if r.EndedBy != types.EndedMaxDuration {
			t.Fatalf("%+v", r)
		}
	})
}

func TestSSENotAnEventStream(t *testing.T) {
	h := newHarness(t)
	var seen sseSeen
	url := sseServer(t, &seen)
	r := stream(t, h, "sse_listen", map[string]any{"url": url + "/json"})
	if r.EndedBy != types.EndedError || len(r.Messages) != 1 || r.Messages[0].Data != `{"error":"unauthorized"}` {
		t.Fatalf("%+v", r)
	}
	mustContain(t, r.Error, "HTTP 401", "application/json")
	if r.Meta["status"] != float64(401) {
		t.Fatalf("meta %v", r.Meta)
	}

	// No response at all is a tool error and ends promptly.
	timed(t, 10*time.Second, func() {
		h.MustFail("sse_listen", map[string]any{"url": "http://127.0.0.1:1/"}, "")
	})

	h.MustFail("sse_listen", map[string]any{"url": url, "method": "PUT"}, "GET or POST")
	h.MustFail("sse_listen", map[string]any{"url": url, "method": "GET", "body": map[string]any{"text": "x"}}, "needs method POST")
}
