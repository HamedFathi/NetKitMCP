package msgtools_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/tcp"
	"github.com/plgd-dev/go-coap/v3/udp"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// coapSeen is what the test server received.
type coapSeen struct {
	Method        codes.Code
	Path          string
	Queries       []string
	ContentFormat int // -1 = none
	Body          []byte
	Accept        int // -1 = none
}

type coapSrv struct {
	udp, tcp string // host:port
	seen     chan coapSeen
	stop     chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	store    map[string][]byte
	bigBody  []byte
}

func (s *coapSrv) record(r *mux.Message) coapSeen {
	seen := coapSeen{Method: r.Code(), ContentFormat: -1, Accept: -1}
	seen.Path, _ = r.Options().Path()
	seen.Queries, _ = r.Options().Queries()
	if cf, err := r.ContentFormat(); err == nil {
		seen.ContentFormat = int(cf)
	}
	if a, err := r.Options().Accept(); err == nil {
		seen.Accept = int(a)
	}
	if b := r.Body(); b != nil {
		seen.Body, _ = io.ReadAll(b)
	}
	select {
	case s.seen <- seen:
	default:
	}
	return seen
}

func (s *coapSrv) expect(t *testing.T) coapSeen {
	t.Helper()
	select {
	case v := <-s.seen:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("CoAP server saw no request")
	}
	return coapSeen{}
}

func (s *coapSrv) router() *mux.Router {
	r := mux.NewRouter()
	r.SetErrorHandler(func(error) {})
	r.HandleFunc("/hello", func(w mux.ResponseWriter, req *mux.Message) {
		seen := s.record(req)
		body := "hello"
		if len(seen.Queries) > 0 {
			body += " " + strings.Join(seen.Queries, "&")
		}
		_ = w.SetResponse(codes.Content, message.TextPlain, bytes.NewReader([]byte(body)),
			message.Option{ID: message.MaxAge, Value: []byte{60}})
	})
	r.HandleFunc("/json", func(w mux.ResponseWriter, req *mux.Message) {
		s.record(req)
		_ = w.SetResponse(codes.Content, message.AppJSON, bytes.NewReader([]byte(`{"t":21.5}`)))
	})
	r.HandleFunc("/bin", func(w mux.ResponseWriter, req *mux.Message) {
		s.record(req)
		_ = w.SetResponse(codes.Content, message.AppOctets, bytes.NewReader([]byte{0, 1, 2, 0xff}))
	})
	r.HandleFunc("/big", func(w mux.ResponseWriter, req *mux.Message) {
		s.record(req)
		_ = w.SetResponse(codes.Content, message.TextPlain, bytes.NewReader(s.bigBody))
	})
	r.HandleFunc("/res", func(w mux.ResponseWriter, req *mux.Message) {
		seen := s.record(req)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch req.Code() {
		case codes.GET:
			b, ok := s.store["res"]
			if !ok {
				_ = w.SetResponse(codes.NotFound, message.TextPlain, bytes.NewReader([]byte("gone")))
				return
			}
			_ = w.SetResponse(codes.Content, message.TextPlain, bytes.NewReader(b))
		case codes.POST:
			s.store["res"] = seen.Body
			_ = w.SetResponse(codes.Created, message.TextPlain, bytes.NewReader([]byte(fmt.Sprintf("created %d", len(seen.Body)))),
				message.Option{ID: message.LocationPath, Value: []byte("res")})
		case codes.PUT:
			s.store["res"] = seen.Body
			_ = w.SetResponse(codes.Changed, message.TextPlain, nil)
		case codes.DELETE:
			delete(s.store, "res")
			_ = w.SetResponse(codes.Deleted, message.TextPlain, nil)
		default:
			_ = w.SetResponse(codes.MethodNotAllowed, message.TextPlain, nil)
		}
	})
	r.HandleFunc("/fail", func(w mux.ResponseWriter, req *mux.Message) {
		s.record(req)
		_ = w.SetResponse(codes.InternalServerError, message.TextPlain, bytes.NewReader([]byte("boom")))
	})
	r.HandleFunc("/obs", func(w mux.ResponseWriter, req *mux.Message) {
		s.record(req)
		obs, err := req.Options().Observe()
		if req.Code() != codes.GET || err != nil || obs != 0 {
			// Plain GET or deregistration (observe=1).
			_ = w.SetResponse(codes.Content, message.TextPlain, bytes.NewReader([]byte("snapshot")))
			return
		}
		cc := w.Conn()
		token := append([]byte(nil), req.Token()...)
		go func() {
			for seq := uint32(2); seq < 200; seq++ {
				m := cc.AcquireMessage(cc.Context())
				m.SetCode(codes.Content)
				m.SetToken(token)
				m.SetContentFormat(message.TextPlain)
				m.SetObserve(seq)
				m.SetBody(bytes.NewReader([]byte(fmt.Sprintf("n%d", seq))))
				err := cc.WriteMessage(m)
				cc.ReleaseMessage(m)
				if err != nil {
					return
				}
				select {
				case <-s.stop:
					return
				case <-cc.Context().Done():
					return
				case <-time.After(40 * time.Millisecond):
				}
			}
		}()
	})
	return r
}

func startCoAP(t *testing.T) *coapSrv {
	t.Helper()
	s := &coapSrv{seen: make(chan coapSeen, 64), stop: make(chan struct{}), store: map[string][]byte{},
		bigBody: bytes.Repeat([]byte("0123456789abcdef"), 400)} // 6400 bytes: block-wise
	router := s.router()

	ul, err := coapnet.NewListenUDP("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	us := udp.NewServer(options.WithMux(router))
	go func() { _ = us.Serve(ul) }()
	s.udp = ul.LocalAddr().String()

	tl, err := coapnet.NewTCPListener("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := tcp.NewServer(options.WithMux(router))
	go func() { _ = ts.Serve(tl) }()
	s.tcp = tl.Addr().String()

	t.Cleanup(func() {
		s.stopOnce.Do(func() { close(s.stop) })
		us.Stop()
		ts.Stop()
		_ = ul.Close()
		_ = tl.Close()
	})
	return s
}

type coapOut struct {
	Code          string `json:"code"`
	CodeName      string `json:"code_name"`
	Success       bool   `json:"success"`
	Type          string `json:"type"`
	ContentFormat string `json:"content_format"`
	Options       []struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"options"`
	Body         string         `json:"body"`
	BodyEncoding string         `json:"body_encoding"`
	SizeBytes    int            `json:"size_bytes"`
	Truncated    bool           `json:"truncated"`
	Request      map[string]any `json:"request"`
	Warnings     []string       `json:"warnings"`
}

func coapCall(t *testing.T, h *tooltest.Harness, args map[string]any) coapOut {
	t.Helper()
	var out coapOut
	h.MustOK("coap_request", args).Decode(t, &out)
	return out
}

func TestCoAPMethods(t *testing.T) {
	s := startCoAP(t)
	h := tooltest.New(t, "messaging")
	for _, scheme := range []string{"coap", "coap+tcp"} {
		t.Run(scheme, func(t *testing.T) {
			host := s.udp
			if scheme == "coap+tcp" {
				host = s.tcp
			}
			base := scheme + "://" + host

			// GET with URL query, extra query and Accept.
			out := coapCall(t, h, map[string]any{"url": base + "/hello?a=1", "query": []string{"b=2"}, "accept": "text/plain"})
			seen := s.expect(t)
			if out.Code != "2.05" || !out.Success || out.Body != "hello a=1&b=2" || out.BodyEncoding != "text" || seen.Method != codes.GET {
				t.Fatalf("GET: %+v", out)
			}
			if seen.Accept != int(message.TextPlain) || strings.Join(seen.Queries, "&") != "a=1&b=2" {
				t.Fatalf("server saw %+v", seen)
			}
			if !strings.Contains(out.ContentFormat, "text/plain") {
				t.Fatalf("content_format = %q", out.ContentFormat)
			}
			foundMaxAge := false
			for _, o := range out.Options {
				if o.Name == "MaxAge" && o.Value == float64(60) {
					foundMaxAge = true
				}
			}
			if !foundMaxAge {
				t.Fatalf("Max-Age option not reported: %+v", out.Options)
			}
			if scheme == "coap" && out.Type == "" {
				t.Fatalf("UDP message type missing: %+v", out)
			}

			// POST JSON: content format derived from the payload.
			out = coapCall(t, h, map[string]any{"url": base + "/res", "method": "POST", "payload": map[string]any{"json": map[string]any{"v": 1}}})
			seen = s.expect(t)
			if out.Code != "2.01" || out.Body != "created 7" || seen.ContentFormat != int(message.AppJSON) || string(seen.Body) != `{"v":1}` {
				t.Fatalf("POST: %+v seen=%+v", out, seen)
			}

			// PUT text with an explicit content_format.
			out = coapCall(t, h, map[string]any{"url": base + "/res", "method": "put", "payload": map[string]any{"text": "<a/>"}, "content_format": "application/xml"})
			seen = s.expect(t)
			if out.Code != "2.04" || out.CodeName != "Changed" || seen.ContentFormat != int(message.AppXML) || string(seen.Body) != "<a/>" {
				t.Fatalf("PUT: %+v seen=%+v", out, seen)
			}
			out = coapCall(t, h, map[string]any{"url": base + "/res"})
			s.expect(t)
			if out.Body != "<a/>" {
				t.Fatalf("GET after PUT: %+v", out)
			}

			// DELETE, then GET returns 4.04 as a result (not a tool error).
			out = coapCall(t, h, map[string]any{"url": base + "/res", "method": "DELETE"})
			s.expect(t)
			if out.Code != "2.02" || !out.Success {
				t.Fatalf("DELETE: %+v", out)
			}
			out = coapCall(t, h, map[string]any{"url": base + "/res"})
			s.expect(t)
			if out.Code != "4.04" || out.Success || out.Body != "gone" {
				t.Fatalf("GET after DELETE: %+v", out)
			}
			out = coapCall(t, h, map[string]any{"url": base + "/nowhere"})
			if out.Code != "4.04" || out.Success {
				t.Fatalf("unknown path: %+v", out)
			}
			out = coapCall(t, h, map[string]any{"url": base + "/fail"})
			s.expect(t)
			if out.Code != "5.00" || out.Success || out.Body != "boom" {
				t.Fatalf("5.00: %+v", out)
			}

			// Content formats on responses.
			out = coapCall(t, h, map[string]any{"url": base + "/json"})
			s.expect(t)
			if out.Body != `{"t":21.5}` || !strings.Contains(out.ContentFormat, "json") {
				t.Fatalf("json: %+v", out)
			}
			out = coapCall(t, h, map[string]any{"url": base + "/bin"})
			s.expect(t)
			if out.BodyEncoding != "base64" || out.Body != "AAEC/w==" {
				t.Fatalf("bin: %+v", out)
			}

			// Block-wise response, and truncation by max_response_bytes.
			out = coapCall(t, h, map[string]any{"url": base + "/big"})
			s.expect(t)
			if out.SizeBytes != len(s.bigBody) || out.Body != string(s.bigBody) || out.Truncated {
				t.Fatalf("big: size=%d truncated=%v", out.SizeBytes, out.Truncated)
			}
		})
	}
}

func TestCoAPPayloads(t *testing.T) {
	s := startCoAP(t)
	h := tooltest.New(t, "messaging")
	base := "coap://" + s.udp

	// Small binary file.
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	p := h.WriteInput("small.bin", data)
	out := coapCall(t, h, map[string]any{"url": base + "/res", "method": "POST", "payload": map[string]any{"file": p}})
	seen := s.expect(t)
	if out.Code != "2.01" || !bytes.Equal(seen.Body, data) || seen.ContentFormat != int(message.AppOctets) {
		t.Fatalf("file POST: %+v seen=%+v", out, seen)
	}
	if out.Request["payload_file"] == nil || out.Request["payload_bytes"] != float64(len(data)) {
		t.Fatalf("payload file not echoed: %+v", out.Request)
	}

	// A larger file goes block-wise (Block1).
	big := bytes.Repeat([]byte("block-wise-"), 700) // 7700 bytes
	p = h.WriteInput("big.txt", big)
	out = coapCall(t, h, map[string]any{"url": base + "/res", "method": "PUT", "payload": map[string]any{"file": p}, "content_format": "0"})
	seen = s.expect(t)
	if out.Code != "2.04" || !bytes.Equal(seen.Body, big) || seen.ContentFormat != 0 {
		t.Fatalf("block-wise PUT: code=%s got %d bytes cf=%d", out.Code, len(seen.Body), seen.ContentFormat)
	}

	// Base64 payload.
	out = coapCall(t, h, map[string]any{"url": base + "/res", "method": "POST", "payload": map[string]any{"base64": "AAEC"}, "content_format": "cbor"})
	seen = s.expect(t)
	if !bytes.Equal(seen.Body, []byte{0, 1, 2}) || seen.ContentFormat != int(message.AppCBOR) {
		t.Fatalf("base64 POST: %+v seen=%+v", out, seen)
	}

	// Non-confirmable request.
	out = coapCall(t, h, map[string]any{"url": base + "/hello", "confirmable": false})
	s.expect(t)
	if out.Code != "2.05" {
		t.Fatalf("NON GET: %+v", out)
	}

	// Truncation.
	out = coapCall(t, h, map[string]any{"url": base + "/big", "max_response_bytes": 100})
	s.expect(t)
	if !out.Truncated || len(out.Body) != 100 {
		t.Fatalf("truncation: truncated=%v len=%d", out.Truncated, len(out.Body))
	}
}

func TestCoAPObserve(t *testing.T) {
	s := startCoAP(t)
	h := tooltest.New(t, "messaging")
	for _, scheme := range []string{"coap", "coap+tcp"} {
		t.Run(scheme, func(t *testing.T) {
			host := s.udp
			if scheme == "coap+tcp" {
				host = s.tcp
			}
			r := h.MustOK("coap_request", map[string]any{"url": scheme + "://" + host + "/obs", "observe": true, "max_notifications": 3, "max_duration_seconds": 5})
			var res types.StreamResult
			r.Decode(t, &res)
			if res.EndedBy != types.EndedMaxMessages || len(res.Messages) != 3 {
				t.Fatalf("unexpected result: %s", r.Raw)
			}
			for _, m := range res.Messages {
				if !strings.HasPrefix(m.Data, "n") || m.Meta["code"] != "2.05" || m.Meta["observe"] == nil {
					t.Fatalf("unexpected notification: %+v", m)
				}
			}
			if res.Meta["first_code"] != "2.05" {
				t.Fatalf("meta: %v", res.Meta)
			}

			// Duration bound.
			start := time.Now()
			r = h.MustOK("coap_request", map[string]any{"url": scheme + "://" + host + "/obs", "observe": true, "max_duration_seconds": 0.4})
			res = types.StreamResult{}
			r.Decode(t, &res)
			if res.EndedBy != types.EndedMaxDuration || len(res.Messages) == 0 || time.Since(start) > 5*time.Second {
				t.Fatalf("unexpected result: %s", r.Raw)
			}

			// A resource that is not observable returns one response.
			r = h.MustOK("coap_request", map[string]any{"url": scheme + "://" + host + "/hello", "observe": true, "max_duration_seconds": 3})
			res = types.StreamResult{}
			r.Decode(t, &res)
			if res.EndedBy != types.EndedComplete || len(res.Messages) != 1 || res.Messages[0].Data != "hello" {
				t.Fatalf("unexpected result: %s", r.Raw)
			}
			if w, _ := res.Meta["warnings"].([]any); len(w) == 0 {
				t.Fatalf("expected a not-observable warning: %v", res.Meta)
			}
		})
	}
	h.MustFail("coap_request", map[string]any{"url": "coap://" + s.udp + "/obs", "observe": true, "method": "POST"}, "observe requires GET")
}

func TestCoAPValidation(t *testing.T) {
	h := tooltest.New(t, "messaging")
	h.MustFail("coap_request", map[string]any{"url": "coaps://127.0.0.1/x"}, "DTLS")
	h.MustFail("coap_request", map[string]any{"url": "http://127.0.0.1/x"}, "unsupported CoAP scheme")
	h.MustFail("coap_request", map[string]any{"url": "coap://127.0.0.1:1/x", "method": "BREW"}, "unsupported CoAP method")
	h.MustFail("coap_request", map[string]any{"url": "coap://127.0.0.1:1/x", "content_format": "nope/nope"}, "content_format")
	h.MustFail("coap_request", map[string]any{"url": "coap://127.0.0.1:1/x", "options": []map[string]any{{"name": "bogus", "value": "1"}}}, "unknown CoAP option")
}

// Peers that never answer must not hang the call.
func TestCoAPUnresponsivePeer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
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
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	h := tooltest.New(t, "messaging")
	for _, args := range []map[string]any{
		{"url": "coap://" + pc.LocalAddr().String() + "/x", "timeout_seconds": 1},
		{"url": "coap://" + pc.LocalAddr().String() + "/x", "timeout_seconds": 1, "observe": true, "max_duration_seconds": 1},
		{"url": "coap+tcp://" + l.Addr().String() + "/x", "timeout_seconds": 1},
		{"url": "coap+tcp://" + l.Addr().String() + "/x", "timeout_seconds": 1, "observe": true, "max_duration_seconds": 1},
	} {
		start := time.Now()
		r := h.Call("coap_request", args)
		el := time.Since(start)
		if el > 6*time.Second {
			t.Fatalf("%v took %s", args, el)
		}
		if !r.IsError {
			// An observe against a silent peer may end by duration; it must not
			// report notifications.
			var res types.StreamResult
			r.Decode(t, &res)
			if len(res.Messages) != 0 {
				t.Fatalf("%v: unexpected result %s", args, r.Raw)
			}
		} else if args["observe"] == nil {
			mustContain(t, r.Text, "no CoAP response")
		}
	}
}

func TestCoAPSSRFBlocked(t *testing.T) {
	s := startCoAP(t)
	h := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("coap_request", map[string]any{"url": "coap://" + s.udp + "/hello"}, "blocked")
	h.MustFail("coap_request", map[string]any{"url": "coap+tcp://" + s.tcp + "/hello"}, "blocked")
	h.MustFail("coap_request", map[string]any{"url": "coap://localhost/hello"}, "blocked")
	h.MustFail("coap_request", map[string]any{"url": "coap://" + s.udp + "/obs", "observe": true}, "blocked")
	out := coapCall(t, h, map[string]any{"url": "coap://" + s.udp + "/hello", "allow_private": true})
	if out.Code != "2.05" {
		t.Fatalf("allow_private: %+v", out)
	}
}
