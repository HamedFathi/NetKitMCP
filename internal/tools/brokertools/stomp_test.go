package brokertools_test

import (
	"strings"
	"testing"
	"time"

	"github.com/go-stomp/stomp/v3/frame"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func TestSTOMPSend(t *testing.T) {
	b := startSTOMP(t, nil, func(f *fakeSTOMP) { f.Users = map[string]string{"guest": "s3cret"} })
	h := tooltest.New(t, "messaging")

	r := h.MustOK("stomp_send", map[string]any{
		"address": "stomp://" + b.Addr, "login": "guest", "passcode": "s3cret", "host": "/vh",
		"destination":     "/queue/orders",
		"payload":         map[string]any{"json": map[string]any{"id": 7}},
		"headers":         map[string]string{"persistent": "true", "priority": "5"},
		"connect_headers": map[string]string{"client-id": "netkit-1"},
	})
	if r.Data["receipt_received"] != true || r.Data["version"] != "1.2" || r.Data["server"] != "fakestomp/1.0" ||
		r.Data["session"] == "" || r.Data["size_bytes"].(float64) != 8 || r.Data["destination"] != "/queue/orders" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if strings.Contains(string(r.Raw), "s3cret") {
		t.Fatalf("passcode echoed: %s", r.Raw)
	}
	c := b.Expect(t, frame.CONNECT)
	if c.Header.Get(frame.Login) != "guest" || c.Header.Get(frame.Passcode) != "s3cret" || c.Header.Get(frame.Host) != "/vh" ||
		!strings.Contains(c.Header.Get(frame.AcceptVersion), "1.2") || c.Header.Get("client-id") != "netkit-1" {
		t.Fatalf("CONNECT headers: %v", c.Header)
	}
	if hb := c.Header.Get(frame.HeartBeat); hb != "0,0" {
		t.Fatalf("heart-beat = %q", hb)
	}
	s := b.Expect(t, frame.SEND)
	if s.Header.Get(frame.Destination) != "/queue/orders" || s.Header.Get(frame.ContentType) != "application/json" ||
		s.Header.Get("persistent") != "true" || s.Header.Get("priority") != "5" || s.Header.Get(frame.Receipt) == "" ||
		string(s.Body) != `{"id":7}` {
		t.Fatalf("SEND frame: %v %q", s.Header, s.Body)
	}
	b.Expect(t, frame.DISCONNECT)

	// auth basic, binary file payload, no receipt, explicit content type.
	data := []byte{0, 1, 2, 0xff}
	p := h.WriteInput("blob.bin", data)
	r = h.MustOK("stomp_send", map[string]any{
		"address": b.Addr, "auth": map[string]any{"type": "basic", "username": "guest", "password": "s3cret"},
		"destination": "/topic/bin", "payload": map[string]any{"file": p}, "receipt": false, "content_type": "application/x-blob",
		"versions": []string{"1.1"},
	})
	if r.Data["receipt_received"] != false || r.Data["version"] != "1.1" || r.Data["file"].(map[string]any)["size_bytes"].(float64) != 4 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	c = b.Expect(t, frame.CONNECT)
	if c.Header.Get(frame.AcceptVersion) != "1.1" {
		t.Fatalf("accept-version = %q", c.Header.Get(frame.AcceptVersion))
	}
	s = b.Expect(t, frame.SEND)
	if s.Header.Get(frame.ContentType) != "application/x-blob" || string(s.Body) != string(data) {
		t.Fatalf("SEND frame: %v %v", s.Header, s.Body)
	}
	if _, ok := s.Header.Contains(frame.Receipt); ok {
		t.Fatalf("receipt requested although receipt=false: %v", s.Header)
	}
}

func TestSTOMPLoginFailure(t *testing.T) {
	b := startSTOMP(t, nil, func(f *fakeSTOMP) { f.Users = map[string]string{"guest": "s3cret"} })
	h := tooltest.New(t, "messaging")
	for _, tool := range []string{"stomp_send", "stomp_subscribe"} {
		r := h.MustFail(tool, map[string]any{"address": b.Addr, "login": "guest", "passcode": "wrong", "destination": "/queue/x", "timeout_seconds": 5}, "Access refused")
		mustNotLeak(t, r.Text, "wrong", "s3cret")
	}
	h.MustFail("stomp_send", map[string]any{"address": b.Addr, "destination": "/queue/x", "auth": map[string]any{"type": "api_key", "key": "k", "value": "v"}}, "not supported")
}

func TestSTOMPErrorFrameOnSend(t *testing.T) {
	b := startSTOMP(t, nil, func(f *fakeSTOMP) { f.ErrorOnSend = true })
	h := tooltest.New(t, "messaging")
	start := time.Now()
	h.MustFail("stomp_send", map[string]any{"address": b.Addr, "destination": "/queue/ro", "payload": map[string]any{"text": "x"}, "timeout_seconds": 5}, "read-only")
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("ERROR frame took %s to surface", el)
	}
}

func TestSTOMPSubscribe(t *testing.T) {
	b := startSTOMP(t, nil, nil)
	h := tooltest.New(t, "messaging")

	// Round trip: send through the tool, then collect it.
	h.MustOK("stomp_send", map[string]any{"address": b.Addr, "destination": "/queue/work", "payload": map[string]any{"text": "job-1"}, "headers": map[string]string{"x-k": "v"}})
	b.Publish("/queue/work", "application/octet-stream", []byte{0, 0xff})
	r := h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/queue/work", "max_messages": 2, "max_duration_seconds": 5,
		"headers": map[string]string{"selector": "x = 1"}, "receipt": true})
	res := stream(t, r)
	if res.EndedBy != types.EndedMaxMessages || len(res.Messages) != 2 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	m := res.Messages[0]
	if m.Data != "job-1" || m.Encoding != "text" || m.Topic != "/queue/work" || m.ID == "" || m.Headers["x-k"] != "v" {
		t.Fatalf("first message: %+v", m)
	}
	if m2 := res.Messages[1]; m2.Encoding != "base64" || m2.Data != "AP8=" || m2.Type != "binary" {
		t.Fatalf("second message: %+v", m2)
	}
	if res.Meta["ack"] != "auto" || res.Meta["version"] != "1.2" {
		t.Fatalf("meta: %v", res.Meta)
	}
	sub := b.Expect(t, frame.SUBSCRIBE)
	if sub.Header.Get(frame.Destination) != "/queue/work" || sub.Header.Get("selector") != "x = 1" || sub.Header.Get(frame.Receipt) == "" {
		t.Fatalf("SUBSCRIBE frame: %v", sub.Header)
	}
	b.Expect(t, frame.UNSUBSCRIBE)

	// Client acks: each message is acknowledged.
	b.Publish("/queue/acked", "text/plain", []byte("a"))
	b.Publish("/queue/acked", "text/plain", []byte("b"))
	r = h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/queue/acked", "ack": "client-individual", "max_messages": 2, "max_duration_seconds": 5})
	res = stream(t, r)
	if len(res.Messages) != 2 || res.Meta["settle"] != "ack" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	sub = b.Expect(t, frame.SUBSCRIBE)
	if sub.Header.Get(frame.Ack) != "client-individual" {
		t.Fatalf("ack header: %v", sub.Header)
	}
	a1, a2 := b.Expect(t, frame.ACK), b.Expect(t, frame.ACK)
	if a1.Header.Get(frame.Id) != "a-"+strings.TrimPrefix(res.Messages[0].ID, "m-") || a2.Header.Get(frame.Id) == "" {
		t.Fatalf("ACK frames: %v / %v", a1.Header, a2.Header)
	}
	if res.Meta["settled"].(float64) != 2 {
		t.Fatalf("settled: %v", res.Meta)
	}

	// settle=nack.
	b.Publish("/queue/nacked", "text/plain", []byte("n"))
	r = h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/queue/nacked", "ack": "client", "settle": "nack", "max_messages": 1, "max_duration_seconds": 5})
	res = stream(t, r)
	if len(res.Messages) != 1 || res.Meta["settle"] != "nack" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	b.Expect(t, frame.NACK)
}

func TestSTOMPSubscribeBounds(t *testing.T) {
	b := startSTOMP(t, nil, nil)
	h := tooltest.New(t, "messaging")

	start := time.Now()
	r := h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/topic/quiet", "max_duration_seconds": 0.5})
	res := stream(t, r)
	if res.EndedBy != types.EndedMaxDuration || len(res.Messages) != 0 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("max_duration took %s", el)
	}

	// Live messages while subscribed, then idle.
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.waitSub(t, "/topic/live")
		b.Publish("/topic/live", "text/plain", []byte("tick"))
	}()
	r = h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/topic/live", "idle_timeout_seconds": 0.5, "max_duration_seconds": 10})
	<-done
	res = stream(t, r)
	if res.EndedBy != types.EndedIdle || len(res.Messages) != 1 || res.Messages[0].Data != "tick" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
}

func TestSTOMPHeartBeat(t *testing.T) {
	b := startSTOMP(t, nil, func(f *fakeSTOMP) { f.HeartBeat = "100,100"; f.SendHeartBeats = true })
	h := tooltest.New(t, "messaging")
	r := h.MustOK("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/topic/hb", "heart_beat_seconds": []float64{0.1, 0.1}, "max_duration_seconds": 1})
	res := stream(t, r)
	if res.EndedBy != types.EndedMaxDuration || res.Error != "" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	c := b.Expect(t, frame.CONNECT)
	if hb := c.Header.Get(frame.HeartBeat); hb != "100,100" {
		t.Fatalf("heart-beat = %q", hb)
	}
	h.MustFail("stomp_send", map[string]any{"address": b.Addr, "destination": "/q", "heart_beat_seconds": []float64{1}}, "heart_beat_seconds")
}

func TestSTOMPTLS(t *testing.T) {
	cfg, caPEM := testTLS(t)
	b := startSTOMP(t, cfg, nil)
	h := tooltest.New(t, "messaging")
	r := h.MustOK("stomp_send", map[string]any{"address": "stomp+ssl://" + b.Addr, "destination": "/queue/tls", "ca_cert": caPEM, "payload": map[string]any{"text": "x"}})
	if tl, _ := r.Data["tls"].(map[string]any); tl == nil || tl["version"] == "" {
		t.Fatalf("expected TLS info: %s", r.Raw)
	}
	r = h.MustOK("stomp_send", map[string]any{"address": b.Addr, "tls": true, "insecure_skip_verify": true, "destination": "/queue/tls"})
	if w, _ := r.Data["warnings"].([]any); len(w) == 0 {
		t.Fatalf("insecure_skip_verify not flagged: %s", r.Raw)
	}
	h.MustFail("stomp_send", map[string]any{"address": "stomp+ssl://" + b.Addr, "destination": "/queue/tls", "timeout_seconds": 5}, "TLS handshake")
}

// A broker that stops responding must not hang any call.
func TestSTOMPUnresponsive(t *testing.T) {
	silent := startSTOMP(t, nil, func(f *fakeSTOMP) { f.SilentConnect = true })
	mute := startSTOMP(t, nil, func(f *fakeSTOMP) { f.SilentAfterConnect = true })
	h := tooltest.New(t, "messaging")
	check := func(name string, max time.Duration, fn func()) {
		t.Helper()
		start := time.Now()
		fn()
		if el := time.Since(start); el > max {
			t.Fatalf("%s took %s", name, el)
		}
	}
	check("send/silent connect", 6*time.Second, func() {
		h.MustFail("stomp_send", map[string]any{"address": silent.Addr, "destination": "/q", "timeout_seconds": 1}, "no CONNECTED frame")
	})
	check("subscribe/silent connect", 6*time.Second, func() {
		h.MustFail("stomp_subscribe", map[string]any{"address": silent.Addr, "destination": "/q", "timeout_seconds": 1}, "no CONNECTED frame")
	})
	check("send/no receipt", 8*time.Second, func() {
		h.MustFail("stomp_send", map[string]any{"address": mute.Addr, "destination": "/q", "payload": map[string]any{"text": "x"}, "timeout_seconds": 1}, "no RECEIPT")
	})
	check("subscribe/no receipt", 10*time.Second, func() {
		h.MustFail("stomp_subscribe", map[string]any{"address": mute.Addr, "destination": "/q", "receipt": true, "timeout_seconds": 1, "max_duration_seconds": 1}, "no RECEIPT")
	})
	check("subscribe/mute broker", 10*time.Second, func() {
		r := h.MustOK("stomp_subscribe", map[string]any{"address": mute.Addr, "destination": "/q", "timeout_seconds": 1, "max_duration_seconds": 0.5})
		if res := stream(t, r); len(res.Messages) != 0 {
			t.Fatalf("unexpected result: %s", r.Raw)
		}
	})
}

func TestSTOMPValidation(t *testing.T) {
	h := tooltest.New(t, "messaging")
	h.MustFail("stomp_send", map[string]any{"address": "127.0.0.1:1", "destination": " "}, "destination")
	h.MustFail("stomp_send", map[string]any{"address": "http://127.0.0.1:1", "destination": "/q"}, "unsupported scheme")
	h.MustFail("stomp_send", map[string]any{"address": "127.0.0.1:1", "destination": "/q", "versions": []string{"2.0"}}, "")
	h.MustFail("stomp_subscribe", map[string]any{"address": "127.0.0.1:1", "destination": "/q", "ack": "maybe"}, "ack must be")
	h.MustFail("stomp_subscribe", map[string]any{"address": "127.0.0.1:1", "destination": "/q", "settle": "drop"}, "settle must be")
}

func TestSTOMPSSRFBlocked(t *testing.T) {
	b := startSTOMP(t, nil, nil)
	h := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("stomp_send", map[string]any{"address": b.Addr, "destination": "/q"}, "blocked")
	h.MustFail("stomp_subscribe", map[string]any{"address": b.Addr, "destination": "/q"}, "blocked")
	h.MustFail("stomp_send", map[string]any{"address": "stomp://localhost:61613", "destination": "/q"}, "blocked")
	h.MustOK("stomp_send", map[string]any{"address": b.Addr, "destination": "/q", "allow_private": true})
}

func mustNotLeak(t *testing.T, s string, secrets ...string) {
	t.Helper()
	for _, x := range secrets {
		if strings.Contains(s, x) {
			t.Fatalf("output leaks %q: %s", x, s)
		}
	}
}
