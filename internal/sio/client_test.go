package sio_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/sio"
	"github.com/HamedFathi/NetKitMCP/internal/sio/siotest"
)

type recorder struct {
	mu   sync.Mutex
	msgs []sio.Message
	ch   chan sio.Message
}

func newRecorder() *recorder { return &recorder{ch: make(chan sio.Message, 256)} }

func (r *recorder) add(m sio.Message) {
	r.mu.Lock()
	r.msgs = append(r.msgs, m)
	r.mu.Unlock()
	r.ch <- m
}

func (r *recorder) next(t *testing.T, kind, event string) sio.Message {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m := <-r.ch:
			if m.Kind == kind && (event == "" || m.Event == event) {
				return m
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s %s", kind, event)
		}
	}
}

func startServer(t *testing.T, s *siotest.Server) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/socket.io/", s)
	ts := httptest.NewServer(mux)
	t.Cleanup(func() { s.Close(); ts.Close() })
	return ts.URL + "/socket.io/"
}

func dial(t *testing.T, url, transport string, upgrade bool, rec *recorder) *sio.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := sio.Dial(ctx, sio.Config{
		Engine:    sio.EngineConfig{URL: url, HTTPClient: hc, Transport: transport, Upgrade: upgrade, Origin: "https://app.example", Header: http.Header{"X-Custom": {"v1"}}},
		OnMessage: rec.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestClientTransports(t *testing.T) {
	for _, tc := range []struct {
		name, transport string
		upgrade         bool
		wantTransport   string
	}{
		{"websocket", sio.TransportWebSocket, false, "websocket"},
		{"polling", sio.TransportPolling, false, "polling"},
		{"polling-upgrade", sio.TransportPolling, true, "websocket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &siotest.Server{PingInterval: 100 * time.Millisecond, Namespaces: []string{"/admin"}}
			url := startServer(t, srv)
			rec := newRecorder()
			c := dial(t, url, tc.transport, tc.upgrade, rec)
			if got := c.Engine().Transport(); got != tc.wantTransport {
				t.Fatalf("transport = %s, want %s", got, tc.wantTransport)
			}
			if _, err := c.Connect(ctx5(t), "/", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Connect(ctx5(t), "/admin", map[string]any{"token": "x"}); err != nil {
				t.Fatal(err)
			}
			// Event with ack, waited synchronously.
			em, err := c.Emit(ctx5(t), "/", "echo", []any{"hi", 1}, nil, sio.EmitOptions{Ack: true, Wait: true})
			if err != nil {
				t.Fatal(err)
			}
			ack, err := c.AwaitAck(ctx5(t), em)
			if err != nil || ack == nil || string(ack.Data) != `["hi",1]` {
				t.Fatalf("ack = %+v, %v", ack, err)
			}
			m := rec.next(t, sio.KindEvent, "echo")
			if string(m.Data) != `["hi",1]` || m.Namespace != "/" {
				t.Fatalf("echo = %+v", m)
			}
			// Binary attachments on another namespace.
			if _, err := c.Emit(ctx5(t), "/admin", "echo", []any{"file"}, [][]byte{{0, 1, 2}, []byte("xyz")}, sio.EmitOptions{}); err != nil {
				t.Fatal(err)
			}
			m = rec.next(t, sio.KindEvent, "echo")
			if m.Namespace != "/admin" || m.Attachments != 2 ||
				string(m.Data) != `["file",{"_binary":true,"base64":"AAEC","size":3},{"_binary":true,"base64":"eHl6","size":3}]` {
				t.Fatalf("binary echo = %+v %s", m, m.Data)
			}
			// Server-initiated ack request.
			if _, err := c.Emit(ctx5(t), "/", "ask", nil, nil, sio.EmitOptions{}); err != nil {
				t.Fatal(err)
			}
			q := rec.next(t, sio.KindEvent, "question")
			if q.AckID == nil {
				t.Fatal("question without ack id")
			}
			if _, err := c.Ack(ctx5(t), "/", *q.AckID, []any{"forty-two"}, nil); err != nil {
				t.Fatal(err)
			}
			a := rec.next(t, sio.KindEvent, "answer")
			if string(a.Data) != `["forty-two"]` {
				t.Fatalf("answer = %s", a.Data)
			}
			// Headers reached the server.
			if _, err := c.Emit(ctx5(t), "/admin", "whoami", nil, nil, sio.EmitOptions{}); err != nil {
				t.Fatal(err)
			}
			w := rec.next(t, sio.KindEvent, "whoami")
			var info []map[string]any
			json.Unmarshal(w.Data, &info)
			if info[0]["origin"] != "https://app.example" || info[0]["x_custom"] != "v1" || info[0]["auth"].(map[string]any)["token"] != "x" {
				t.Fatalf("whoami = %s", w.Data)
			}
			// Pings answered.
			deadline := time.Now().Add(3 * time.Second)
			for srv.Pongs.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if srv.Pongs.Load() < 2 {
				t.Fatalf("pongs = %d", srv.Pongs.Load())
			}
			if tc.transport == sio.TransportPolling && srv.CookieMisses.Load() != 0 {
				t.Fatalf("sticky cookie missing on %d requests", srv.CookieMisses.Load())
			}
			if tc.upgrade && srv.Upgrades.Load() != 1 {
				t.Fatalf("upgrades = %d", srv.Upgrades.Load())
			}
			// Server-side namespace disconnect.
			c.Emit(ctx5(t), "/admin", "kick", nil, nil, sio.EmitOptions{})
			d := rec.next(t, sio.KindDisconnect, "")
			if d.Namespace != "/admin" {
				t.Fatalf("disconnect = %+v", d)
			}
			if _, err := c.Emit(ctx5(t), "/admin", "echo", nil, nil, sio.EmitOptions{}); err == nil || !strings.Contains(err.Error(), "disconnected") {
				t.Fatalf("emit on disconnected namespace: %v", err)
			}
			// Server closes the engine connection.
			c.Emit(ctx5(t), "/", "bye", nil, nil, sio.EmitOptions{})
			cl := rec.next(t, sio.KindClose, "")
			if cl.Err == "" {
				t.Fatalf("close = %+v", cl)
			}
		})
	}
}

func TestClientConnectErrors(t *testing.T) {
	srv := &siotest.Server{AuthToken: "secret", Namespaces: []string{"/admin"}}
	url := startServer(t, srv)
	rec := newRecorder()
	c := dial(t, url, sio.TransportWebSocket, false, rec)
	_, err := c.Connect(ctx5(t), "/", map[string]any{"token": "wrong"})
	var ce *sio.ConnectError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Connect(ctx5(t), "/nope", map[string]any{"token": "secret"}); err == nil || !strings.Contains(err.Error(), "Invalid namespace") {
		t.Fatalf("err = %v", err)
	}
	info, err := c.Connect(ctx5(t), "/", map[string]any{"token": "secret"})
	if err != nil || info.State != sio.StateConnected || info.SID == "" {
		t.Fatalf("info = %+v, %v", info, err)
	}
	if _, err := c.Connect(ctx5(t), "/", []any{1}); err == nil {
		t.Fatal("expected error for non-object auth")
	}
}

func TestClientLocalClose(t *testing.T) {
	for _, tr := range []string{sio.TransportWebSocket, sio.TransportPolling} {
		srv := &siotest.Server{}
		url := startServer(t, srv)
		rec := newRecorder()
		c := dial(t, url, tr, false, rec)
		if _, err := c.Connect(ctx5(t), "/", nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		m := rec.next(t, sio.KindClose, "")
		if m.Err != "" {
			t.Fatalf("%s: local close reported error %q", tr, m.Err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for srv.Sessions() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if srv.Sessions() != 0 {
			t.Fatalf("%s: server still has %d sessions", tr, srv.Sessions())
		}
	}
}
