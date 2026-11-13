package msgtools_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type natsSrv struct {
	srv   *natsserver.Server
	url   string // nats://127.0.0.1:port
	ws    string // ws://127.0.0.1:port (when natsOpts.ws)
	caPEM string
}

type natsOpts struct {
	user, pass string
	token      string
	tls        bool
	ws         bool
	nkey       string // allowed user NKey public key
}

func startNATS(t *testing.T, o natsOpts) *natsSrv {
	t.Helper()
	opts := &natsserver.Options{
		Host:          "127.0.0.1",
		Port:          -1,
		NoLog:         true,
		NoSigs:        true,
		Username:      o.user,
		Password:      o.pass,
		Authorization: o.token,
		AuthTimeout:   2,
	}
	if o.nkey != "" {
		opts.Nkeys = []*natsserver.NkeyUser{{Nkey: o.nkey}}
	}
	var caPEM, wsURL string
	if o.ws {
		port := freePort(t)
		opts.Websocket = natsserver.WebsocketOpts{Host: "127.0.0.1", Port: port, NoTLS: true}
		wsURL = fmt.Sprintf("ws://127.0.0.1:%d", port)
	}
	if o.tls {
		cert, pemStr := testCert(t)
		caPEM = pemStr
		opts.TLS = true
		opts.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		opts.TLSTimeout = 2
	}
	s, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	return &natsSrv{srv: s, url: s.ClientURL(), ws: wsURL, caPEM: caPEM}
}

// raw connects a plain nats.go client (as the test peer).
func (s *natsSrv) raw(t *testing.T, opts ...nats.Option) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(s.url, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func nextMsg(t *testing.T, sub *nats.Subscription) *nats.Msg {
	t.Helper()
	m, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("no message on %q: %v", sub.Subject, err)
	}
	return m
}

// pubLoop publishes from the raw client until stopped (the tool subscribes
// asynchronously, so a one-shot publish could race the subscription).
func pubLoop(nc *nats.Conn, subjects ...string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tk := time.NewTicker(30 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				for _, s := range subjects {
					_ = nc.PublishMsg(&nats.Msg{Subject: s, Data: []byte("tick " + s), Header: nats.Header{"X-Src": []string{"loop"}}})
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

func TestNATSPublish(t *testing.T) {
	s := startNATS(t, natsOpts{})
	nc := s.raw(t)
	sub, err := nc.SubscribeSync("orders.>")
	if err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	h := tooltest.New(t, "messaging")

	// Text payload with headers and a reply subject.
	r := h.MustOK("nats_publish", map[string]any{
		"url": s.url, "subject": "orders.created",
		"payload":  map[string]any{"json": map[string]any{"id": 7}},
		"headers":  map[string]string{"X-Tenant": "acme", "Authorization": "Bearer secret-token"},
		"reply_to": "orders.replies",
	})
	var out struct {
		Server    string `json:"server"`
		ServerID  string `json:"server_id"`
		Published struct {
			Subject string            `json:"subject"`
			ReplyTo string            `json:"reply_to"`
			Bytes   int               `json:"bytes"`
			Headers map[string]string `json:"headers"`
		} `json:"published"`
		Flushed bool `json:"flushed"`
	}
	r.Decode(t, &out)
	if !out.Flushed || out.Published.Subject != "orders.created" || out.Published.Bytes != 8 || out.ServerID == "" || out.Published.ReplyTo != "orders.replies" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if strings.Contains(string(r.Raw), "secret-token") {
		t.Fatalf("Authorization header echoed: %s", r.Raw)
	}
	m := nextMsg(t, sub)
	if string(m.Data) != `{"id":7}` || m.Header.Get("X-Tenant") != "acme" || m.Reply != "orders.replies" {
		t.Fatalf("received %q headers=%v reply=%q", m.Data, m.Header, m.Reply)
	}

	// Binary via base64.
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "orders.bin", "payload": map[string]any{"base64": "AAEC/w=="}})
	if m := nextMsg(t, sub); !bytes.Equal(m.Data, []byte{0, 1, 2, 0xff}) {
		t.Fatalf("base64 payload = %v", m.Data)
	}

	// Binary via file.
	data := []byte{0xde, 0xad, 0xbe, 0xef, 0, 1}
	p := h.WriteInput("blob.bin", data)
	r = h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "orders.file", "payload": map[string]any{"file": p}})
	var fout struct {
		Published struct {
			Bytes       int `json:"bytes"`
			PayloadFile struct {
				SHA256    string `json:"sha256"`
				SizeBytes int64  `json:"size_bytes"`
			} `json:"payload_file"`
		} `json:"published"`
	}
	r.Decode(t, &fout)
	sum := sha256.Sum256(data)
	if fout.Published.Bytes != len(data) || fout.Published.PayloadFile.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected file result: %s", r.Raw)
	}
	if m := nextMsg(t, sub); !bytes.Equal(m.Data, data) {
		t.Fatalf("file payload = %v", m.Data)
	}

	// Empty payload.
	h.MustOK("nats_publish", map[string]any{"url": strings.TrimPrefix(s.url, "nats://"), "subject": "orders.empty"})
	if m := nextMsg(t, sub); len(m.Data) != 0 || m.Subject != "orders.empty" {
		t.Fatalf("empty payload = %q on %s", m.Data, m.Subject)
	}
}

func TestNATSRequest(t *testing.T) {
	s := startNATS(t, natsOpts{})
	nc := s.raw(t)
	if _, err := nc.Subscribe("svc.echo", func(m *nats.Msg) {
		reply := nats.NewMsg(m.Reply)
		reply.Header.Set("X-Echo", m.Header.Get("X-Req"))
		reply.Data = append([]byte("echo: "), m.Data...)
		_ = m.RespondMsg(reply)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Subscribe("svc.bin", func(m *nats.Msg) { _ = m.Respond([]byte{0, 0xff, 0x10}) }); err != nil {
		t.Fatal(err)
	}
	// A responder that never answers (for the timeout case).
	if _, err := nc.Subscribe("svc.silent", func(*nats.Msg) {}); err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	h := tooltest.New(t, "messaging")

	r := h.MustOK("nats_request", map[string]any{
		"url": s.url, "subject": "svc.echo",
		"payload": map[string]any{"text": "hi"},
		"headers": map[string]string{"X-Req": "42"},
	})
	var out struct {
		Request struct {
			Subject string `json:"subject"`
			Bytes   int    `json:"bytes"`
		} `json:"request"`
		Reply struct {
			Data      string            `json:"data"`
			Encoding  string            `json:"encoding"`
			Headers   map[string]string `json:"headers"`
			SizeBytes int               `json:"size_bytes"`
		} `json:"reply"`
	}
	r.Decode(t, &out)
	if out.Reply.Data != "echo: hi" || out.Reply.Encoding != "text" || out.Reply.Headers["X-Echo"] != "42" || out.Request.Bytes != 2 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}

	r = h.MustOK("nats_request", map[string]any{"url": s.url, "subject": "svc.bin"})
	r.Decode(t, &out)
	if out.Reply.Encoding != "base64" || out.Reply.Data != "AP8Q" || out.Reply.SizeBytes != 3 {
		t.Fatalf("unexpected binary reply: %s", r.Raw)
	}

	h.MustFail("nats_request", map[string]any{"url": s.url, "subject": "nobody.home", "timeout_seconds": 5}, "no responders")

	start := time.Now()
	h.MustFail("nats_request", map[string]any{"url": s.url, "subject": "svc.silent", "timeout_seconds": 1}, "no reply")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("request timeout took %s", el)
	}

	h.MustFail("nats_request", map[string]any{"url": s.url, "subject": "svc.echo", "reply_to": "x"}, "reply_to")
}

func TestNATSSubscribeWildcards(t *testing.T) {
	s := startNATS(t, natsOpts{})
	nc := s.raw(t)
	stop := pubLoop(nc, "sensors.a.temp", "sensors.b.humidity", "events.x.y.z")
	defer stop()
	h := tooltest.New(t, "messaging")

	// '*' matches exactly one token.
	r := h.MustOK("nats_subscribe", map[string]any{"url": s.url, "subject": "sensors.*.temp", "max_messages": 3, "max_duration_seconds": 5})
	var res types.StreamResult
	r.Decode(t, &res)
	in := inMessages(res)
	if res.EndedBy != types.EndedMaxMessages || len(in) != 3 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	for _, m := range in {
		if m.Topic != "sensors.a.temp" || m.Data != "tick sensors.a.temp" || m.Headers["X-Src"] != "loop" || m.Meta["subscription"] != "sensors.*.temp" {
			t.Fatalf("unexpected message: %+v", m)
		}
	}

	// '>' matches the rest; several subjects at once.
	r = h.MustOK("nats_subscribe", map[string]any{"url": s.url, "subjects": []string{"events.>", "sensors.b.*"}, "max_messages": 6, "max_duration_seconds": 5})
	res = types.StreamResult{}
	r.Decode(t, &res)
	seen := map[string]bool{}
	for _, m := range inMessages(res) {
		seen[m.Topic] = true
	}
	if res.EndedBy != types.EndedMaxMessages || !seen["events.x.y.z"] || !seen["sensors.b.humidity"] || seen["sensors.a.temp"] {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
}

func TestNATSSubscribeBounds(t *testing.T) {
	s := startNATS(t, natsOpts{})
	h := tooltest.New(t, "messaging")

	// max_duration on a quiet subject.
	start := time.Now()
	r := h.MustOK("nats_subscribe", map[string]any{"url": s.url, "subject": "quiet.>", "max_duration_seconds": 0.5})
	var res types.StreamResult
	r.Decode(t, &res)
	if res.EndedBy != types.EndedMaxDuration || len(res.Messages) != 0 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("max_duration took %s", el)
	}

	// idle after the publish_first message comes back; headers, binary
	// payload and reply subject round-trip.
	r = h.MustOK("nats_subscribe", map[string]any{
		"url": s.url, "subject": "loop.*",
		"publish_first": map[string]any{
			"subject": "loop.one", "payload": map[string]any{"base64": "AAEC"},
			"headers": map[string]string{"X-K": "v"}, "reply_to": "loop.reply",
		},
		"idle_timeout_seconds": 0.4, "max_duration_seconds": 5,
	})
	res = types.StreamResult{}
	r.Decode(t, &res)
	in := inMessages(res)
	if res.EndedBy != types.EndedIdle || len(in) != 1 || len(res.Messages) != 2 || res.Messages[0].Dir != "out" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if in[0].Encoding != "base64" || in[0].Data != "AAEC" || in[0].Headers["X-K"] != "v" || in[0].Meta["reply"] != "loop.reply" {
		t.Fatalf("unexpected message: %+v", in[0])
	}
	if pub, _ := res.Meta["published"].(map[string]any); pub == nil || pub["subject"] != "loop.one" {
		t.Fatalf("published meta missing: %v", res.Meta)
	}
}

func TestNATSSubscribeQueueGroup(t *testing.T) {
	s := startNATS(t, natsOpts{})
	nc := s.raw(t)
	// Another member of the same queue group shares the load.
	other, err := nc.QueueSubscribeSync("jobs.*", "workers")
	if err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	stop := pubLoop(nc, "jobs.a")
	defer stop()
	h := tooltest.New(t, "messaging")
	r := h.MustOK("nats_subscribe", map[string]any{"url": s.url, "subject": "jobs.*", "queue": "workers", "max_messages": 3, "max_duration_seconds": 10})
	var res types.StreamResult
	r.Decode(t, &res)
	if res.EndedBy != types.EndedMaxMessages || len(inMessages(res)) != 3 || res.Meta["queue"] != "workers" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	// The other member received messages too (load balanced, not fan-out).
	if _, err := other.NextMsg(3 * time.Second); err != nil {
		t.Fatalf("queue peer received nothing: %v", err)
	}
}

func TestNATSAuth(t *testing.T) {
	s := startNATS(t, natsOpts{user: "alice", pass: "s3cret"})
	h := tooltest.New(t, "messaging")
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "a.b", "username": "alice", "password": "s3cret"})
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "a.b", "auth": map[string]any{"type": "basic", "username": "alice", "password": "s3cret"}})
	for _, tool := range []string{"nats_publish", "nats_request", "nats_subscribe"} {
		args := map[string]any{"url": s.url, "subject": "a.b", "username": "alice", "password": "wrong"}
		if tool == "nats_subscribe" {
			args["max_duration_seconds"] = 1
		}
		r := h.MustFail(tool, args, "authentication failed")
		for _, secret := range []string{"wrong", "s3cret"} {
			if strings.Contains(r.Text, secret) {
				t.Fatalf("error leaks the password: %s", r.Text)
			}
		}
	}
	h.MustFail("nats_publish", map[string]any{"url": s.url, "subject": "a.b"}, "authentication failed")
	h.MustFail("nats_publish", map[string]any{"url": s.url, "subject": "a.b", "auth": map[string]any{"type": "api_key", "key": "x", "value": "y"}}, "not supported for NATS")

	// Credentials embedded in the URL must not be echoed.
	u := strings.Replace(s.url, "nats://", "nats://alice:s3cret@", 1)
	r := h.MustOK("nats_publish", map[string]any{"url": u, "subject": "a.b"})
	if strings.Contains(string(r.Raw), "s3cret") {
		t.Fatalf("URL password echoed: %s", r.Raw)
	}

	ts := startNATS(t, natsOpts{token: "tok-123"})
	h.MustOK("nats_publish", map[string]any{"url": ts.url, "subject": "a.b", "token": "tok-123"})
	h.MustOK("nats_publish", map[string]any{"url": ts.url, "subject": "a.b", "auth": map[string]any{"type": "bearer", "token": "tok-123"}})
	r = h.MustFail("nats_publish", map[string]any{"url": ts.url, "subject": "a.b", "token": "nope"}, "authentication failed")
	if strings.Contains(r.Text, "nope") || strings.Contains(r.Text, "tok-123") {
		t.Fatalf("error leaks the token: %s", r.Text)
	}
}

func TestNATSNKey(t *testing.T) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	s := startNATS(t, natsOpts{nkey: pub})
	h := tooltest.New(t, "messaging")
	r := h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "nk.x", "nkey_seed": string(seed)})
	if strings.Contains(string(r.Raw), string(seed)) {
		t.Fatalf("seed echoed: %s", r.Raw)
	}
	p := h.WriteInput("user.nk", append(seed, "\n"...))
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "nk.x", "nkey_seed": p})
	other, _ := nkeys.CreateUser()
	oseed, _ := other.Seed()
	h.MustFail("nats_publish", map[string]any{"url": s.url, "subject": "nk.x", "nkey_seed": string(oseed)}, "authentication failed")
	h.MustFail("nats_publish", map[string]any{"url": s.url, "subject": "nk.x", "nkey_seed": "SUnotaseed"}, "nkey_seed")
}

func TestNATSTLS(t *testing.T) {
	s := startNATS(t, natsOpts{tls: true})
	tlsURL := strings.Replace(s.url, "nats://", "tls://", 1)
	h := tooltest.New(t, "messaging")
	r := h.MustOK("nats_publish", map[string]any{"url": tlsURL, "subject": "secure.x", "ca_cert": s.caPEM})
	var out struct {
		TLS *struct {
			Version            string `json:"version"`
			InsecureSkipVerify bool   `json:"insecure_skip_verify"`
		} `json:"tls"`
		Warnings []string `json:"warnings"`
	}
	r.Decode(t, &out)
	if out.TLS == nil || out.TLS.Version == "" || len(out.Warnings) != 0 {
		t.Fatalf("expected TLS info: %s", r.Raw)
	}
	// ca_cert alone on a nats:// URL also upgrades.
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "secure.x", "ca_cert": s.caPEM})
	r = h.MustOK("nats_publish", map[string]any{"url": tlsURL, "subject": "secure.x", "insecure_skip_verify": true})
	out.Warnings = nil
	r.Decode(t, &out)
	if out.TLS == nil || !out.TLS.InsecureSkipVerify || len(out.Warnings) == 0 {
		t.Fatalf("insecure_skip_verify not flagged: %s", r.Raw)
	}
	h.MustFail("nats_publish", map[string]any{"url": tlsURL, "subject": "secure.x"}, "certificate")
}

func TestNATSWebSocket(t *testing.T) {
	s := startNATS(t, natsOpts{ws: true})
	nc := s.raw(t)
	sub, err := nc.SubscribeSync("ws.>")
	if err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	h := tooltest.New(t, "messaging")
	h.MustOK("nats_publish", map[string]any{"url": s.ws, "subject": "ws.pub", "payload": map[string]any{"text": "over ws"}})
	if m := nextMsg(t, sub); string(m.Data) != "over ws" {
		t.Fatalf("payload = %q", m.Data)
	}
	r := h.MustOK("nats_subscribe", map[string]any{"url": s.ws, "subject": "ws.echo",
		"publish_first": map[string]any{"subject": "ws.echo", "payload": map[string]any{"text": "e"}}, "max_messages": 1, "max_duration_seconds": 5})
	var res types.StreamResult
	r.Decode(t, &res)
	if res.EndedBy != types.EndedMaxMessages || len(inMessages(res)) != 1 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	hb := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	hb.MustFail("nats_publish", map[string]any{"url": s.ws, "subject": "x"}, "blocked")
}

func TestNATSValidation(t *testing.T) {
	h := tooltest.New(t, "messaging")
	h.MustFail("nats_publish", map[string]any{"url": "nats://127.0.0.1:1", "subject": "a.*"}, "wildcard")
	h.MustFail("nats_publish", map[string]any{"url": "nats://127.0.0.1:1", "subject": "a..b"}, "empty token")
	h.MustFail("nats_publish", map[string]any{"url": "http://127.0.0.1:1", "subject": "a"}, "unsupported NATS URL scheme")
	h.MustFail("nats_subscribe", map[string]any{"url": "nats://127.0.0.1:1"}, "subject")
	h.MustFail("nats_subscribe", map[string]any{"url": "nats://127.0.0.1:1", "subject": "a.>.b"}, "last token")
	h.MustFail("nats_subscribe", map[string]any{"url": "nats://127.0.0.1:1", "subject": "a", "publish_first": map[string]any{"subject": "x.*"}}, "publish_first")
}

// A peer that accepts TCP but never speaks NATS must not hang the call.
func TestNATSUnresponsivePeer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	h := tooltest.New(t, "messaging")
	url := "nats://" + l.Addr().String()
	for _, tool := range []string{"nats_publish", "nats_request", "nats_subscribe"} {
		start := time.Now()
		h.MustFail(tool, map[string]any{"url": url, "subject": "a", "timeout_seconds": 1}, "")
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("%s took %s against a silent peer", tool, el)
		}
	}
}

func TestNATSSSRFBlocked(t *testing.T) {
	s := startNATS(t, natsOpts{})
	h := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("nats_publish", map[string]any{"url": s.url, "subject": "x"}, "blocked")
	h.MustFail("nats_request", map[string]any{"url": s.url, "subject": "x"}, "blocked")
	h.MustFail("nats_subscribe", map[string]any{"url": s.url, "subject": "x"}, "blocked")
	h.MustFail("nats_publish", map[string]any{"url": "nats://localhost:4222", "subject": "x"}, "blocked")
	h.MustOK("nats_publish", map[string]any{"url": s.url, "subject": "x", "allow_private": true})
}
