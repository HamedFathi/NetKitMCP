package grpctools_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// frame renders a gRPC-Web / Connect envelope (written independently of
// the package under test).
func frame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func unframe(b []byte) ([]byte, error) {
	if len(b) < 5 || b[0] != 0 || int(binary.BigEndian.Uint32(b[1:5])) != len(b)-5 {
		return nil, fmt.Errorf("bad request envelope (%d bytes)", len(b))
	}
	return b[5:], nil
}

type webServer struct {
	*httptest.Server
	env    *echoEnv
	active atomic.Int32
	last   atomic.Value // last request headers (http.Header)
}

func (s *webServer) waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("HTTP handler still running: the client did not abandon the stream")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sleepReq(r *http.Request, ms int) bool {
	if ms <= 0 {
		return true
	}
	select {
	case <-r.Context().Done():
		return false
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return true
	}
}

// startGRPCWeb serves the echo service over gRPC-Web (binary and text).
func startGRPCWeb(t *testing.T) *webServer {
	ws := &webServer{env: newEchoEnv(t)}
	e := ws.env
	ws.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws.active.Add(1)
		defer ws.active.Add(-1)
		ws.last.Store(r.Header.Clone())
		ct := r.Header.Get("Content-Type")
		if r.Method != http.MethodPost || !strings.HasPrefix(ct, "application/grpc-web") || r.Header.Get("X-Grpc-Web") != "1" {
			http.Error(w, "not a gRPC-Web request", http.StatusUnsupportedMediaType)
			return
		}
		text := strings.HasPrefix(ct, "application/grpc-web-text")
		body, _ := io.ReadAll(r.Body)
		if text {
			var err error
			if body, err = base64.StdEncoding.DecodeString(string(body)); err != nil {
				http.Error(w, "bad base64", http.StatusBadRequest)
				return
			}
		}
		payload, err := unframe(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := e.decodeBinary(payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		method := path.Base(r.URL.Path)
		if path.Dir(r.URL.Path) != "/prefix/"+svcName || (method != "Unary" && method != "ServerStream") {
			http.NotFound(w, r)
			return
		}
		rct := "application/grpc-web+proto"
		if text {
			rct = "application/grpc-web-text+proto"
		}
		w.Header().Set("Content-Type", rct)
		w.Header().Set("X-Echo-Header", "h1")
		fl := w.(http.Flusher)
		write := func(flag byte, p []byte) {
			f := frame(flag, p)
			if text {
				// Each frame is base64-encoded (and padded) on its own.
				f = []byte(base64.StdEncoding.EncodeToString(f))
			}
			w.Write(f)
			fl.Flush()
		}
		trailers := func(code int) {
			var b strings.Builder
			fmt.Fprintf(&b, "grpc-status: %d\r\n", code)
			if code != 0 {
				st, _ := proto.Marshal(failStatus(code).Proto())
				fmt.Fprintf(&b, "grpc-message: %s\r\n", strings.ReplaceAll("requested failure: 100% on purpose", "%", "%25"))
				fmt.Fprintf(&b, "grpc-status-details-bin: %s\r\n", base64.RawStdEncoding.EncodeToString(st))
			}
			b.WriteString("X-Echo-Trailer: t1\r\n")
			write(0x80, []byte(b.String()))
		}
		switch method {
		case "Unary":
			if req.FailCode != 0 {
				// Trailers-only response: the status is in the headers.
				st, _ := proto.Marshal(failStatus(req.FailCode).Proto())
				w.Header().Set("Grpc-Status", strconv.Itoa(req.FailCode))
				w.Header().Set("Grpc-Message", "requested failure: 100%25 on purpose")
				w.Header().Set("Grpc-Status-Details-Bin", base64.StdEncoding.EncodeToString(st))
				w.WriteHeader(http.StatusOK)
				return
			}
			write(0, e.encodeBinary(echoResp{Text: req.Text, Data: req.Data, Items: req.Items,
				Metadata: map[string]string{"x-custom": r.Header.Get("X-Custom"), "grpc-timeout": r.Header.Get("Grpc-Timeout")}}))
			trailers(0)
		case "ServerStream":
			for i := 0; req.Count < 0 || i < req.Count; i++ {
				write(0, e.encodeBinary(echoResp{Text: fmt.Sprintf("%s-%d", req.Text, i), Index: i}))
				if !sleepReq(r, req.DelayMs) {
					return
				}
			}
			if req.Text == "truncate" {
				// The body ends in the middle of a frame.
				w.Write(frame(0, []byte("partial"))[:6])
				return
			}
			trailers(req.FailCode)
		}
	}))
	t.Cleanup(ws.Close)
	return ws
}

var connectCodes = map[int]string{3: "invalid_argument", 5: "not_found", 9: "failed_precondition", 16: "unauthenticated"}

func connectHTTP(code string) int {
	switch code {
	case "invalid_argument", "failed_precondition":
		return 400
	case "not_found":
		return 404
	case "unauthenticated":
		return 401
	}
	return 500
}

func connectErr(code int) map[string]any {
	ei, _ := proto.Marshal(&errdetails.ErrorInfo{Reason: "TEST_FAILURE", Domain: "netkit.test"})
	return map[string]any{
		"code": connectCodes[code], "message": "requested failure",
		"details": []any{map[string]any{"type": "google.rpc.ErrorInfo", "value": base64.RawStdEncoding.EncodeToString(ei)}},
	}
}

// startConnect serves the echo service with the Connect protocol.
func startConnect(t *testing.T) *webServer {
	ws := &webServer{env: newEchoEnv(t)}
	e := ws.env
	ws.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws.active.Add(1)
		defer ws.active.Add(-1)
		ws.last.Store(r.Header.Clone())
		if r.Header.Get("Connect-Protocol-Version") != "1" {
			http.Error(w, "missing Connect-Protocol-Version", http.StatusBadRequest)
			return
		}
		ct := r.Header.Get("Content-Type")
		streaming := strings.HasPrefix(ct, "application/connect+")
		codec := strings.TrimPrefix(strings.TrimPrefix(ct, "application/connect+"), "application/")
		body, _ := io.ReadAll(r.Body)
		if streaming {
			var err error
			if body, err = unframe(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		var req echoReq
		switch codec {
		case "json":
			m := e.newReq()
			if err := protojson.Unmarshal(body, m); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"code": "invalid_argument", "message": err.Error()})
				return
			}
			req = e.decode(m)
		case "proto":
			var err error
			if req, err = e.decodeBinary(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "bad codec", http.StatusUnsupportedMediaType)
			return
		}
		enc := func(r echoResp) []byte {
			if codec == "proto" {
				return e.encodeBinary(r)
			}
			b, _ := protojson.Marshal(e.encode(r))
			return b
		}
		method := path.Base(r.URL.Path)
		w.Header().Set("X-Echo-Header", "h1")
		if !streaming {
			if method != "Unary" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(404)
				w.Write([]byte(`{"code":"unimplemented","message":"no such method"}`))
				return
			}
			if req.FailCode != 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(connectHTTP(connectCodes[req.FailCode]))
				json.NewEncoder(w).Encode(connectErr(req.FailCode))
				return
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Trailer-X-Echo-Trailer", "t1")
			w.Write(enc(echoResp{Text: req.Text, Data: req.Data, Metadata: map[string]string{
				"x-custom": r.Header.Get("X-Custom"), "connect-timeout-ms": r.Header.Get("Connect-Timeout-Ms")}}))
			return
		}
		w.Header().Set("Content-Type", ct)
		fl := w.(http.Flusher)
		for i := 0; req.Count < 0 || i < req.Count; i++ {
			w.Write(frame(0, enc(echoResp{Text: fmt.Sprintf("%s-%d", req.Text, i), Index: i})))
			fl.Flush()
			if !sleepReq(r, req.DelayMs) {
				return
			}
		}
		if req.Text == "truncate" {
			w.Write(frame(0, []byte("partial"))[:6])
			return
		}
		end := map[string]any{"metadata": map[string][]string{"x-echo-trailer": {"t1"}}}
		if req.FailCode != 0 {
			end["error"] = connectErr(req.FailCode)
		}
		b, _ := json.Marshal(end)
		w.Write(frame(0x02, b))
	}))
	t.Cleanup(ws.Close)
	return ws
}

type webResult struct {
	types.StreamResult
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Protocol         string            `json:"protocol"`
	Kind             string            `json:"kind"`
	HTTPStatus       int               `json:"http_status"`
	Status           statusOut         `json:"status"`
	ConnectCode      string            `json:"connect_code"`
	Response         json.RawMessage   `json:"response"`
	Headers          map[string]string `json:"headers"`
	Trailers         map[string]string `json:"trailers"`
	DescriptorSource string            `json:"descriptor_source"`
}

func (w webResult) resp(t *testing.T) echoResp {
	t.Helper()
	var r echoResp
	if err := json.Unmarshal(w.Response, &r); err != nil {
		t.Fatalf("response %s: %v", w.Response, err)
	}
	return r
}

func (w webResult) texts(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range w.Messages {
		out = append(out, mustJSON(t, m.Data)["text"].(string))
	}
	return out
}

func web(t *testing.T, h *tooltest.Harness, tool string, a map[string]any) webResult {
	t.Helper()
	var out webResult
	h.MustOK(tool, a).Decode(t, &out)
	return out
}

func TestGRPCWeb(t *testing.T) {
	ws := startGRPCWeb(t)
	h := tooltest.New(t, "grpc")
	p := writeProtos(h)
	ds := writeDescriptorSet(t, h, ws.env.reg)
	base := map[string]any{"url": ws.URL + "/prefix/", "proto_files": []string{p}}

	for _, format := range []string{"binary", "text"} {
		t.Run(format, func(t *testing.T) {
			pname := "grpc-web"
			if format == "text" {
				pname = "grpc-web-text"
			}
			blob := h.WriteInput("web.bin", []byte{0, 1, 2, 3})
			out := web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + "/Unary",
				"request":  map[string]any{"text": "hello", "data": map[string]any{"$file": blob}},
				"metadata": map[string]string{"X-Custom": "c1"}}))
			r := out.resp(t)
			if out.Status.Code != 0 || out.HTTPStatus != 200 || out.Protocol != pname || out.Kind != "unary" || r.Text != "hello" || string(r.Data) != "\x00\x01\x02\x03" {
				t.Fatalf("unary = %+v", out)
			}
			if r.Metadata["x-custom"] != "c1" || r.Metadata["grpc-timeout"] == "" {
				t.Errorf("server saw %v", r.Metadata)
			}
			if out.Headers["x-echo-header"] != "h1" || out.Trailers["x-echo-trailer"] != "t1" || out.Trailers["grpc-status"] != "0" {
				t.Errorf("headers=%v trailers=%v", out.Headers, out.Trailers)
			}
			if out.URL != ws.URL+"/prefix/"+svcName+"/Unary" {
				t.Errorf("url = %s", out.URL)
			}
			if got := ws.last.Load().(http.Header).Get("Content-Type"); !strings.HasPrefix(got, "application/"+pname) {
				t.Errorf("request content type = %s", got)
			}

			// Trailers-only error.
			out = web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + ".Unary", "request": map[string]any{"failCode": 5}}))
			if out.Status.Name != "NOT_FOUND" || out.Status.Message != "requested failure: 100% on purpose" || len(out.Status.Details) != 1 ||
				out.Status.Details[0]["reason"] != "TEST_FAILURE" || out.Response != nil {
				t.Fatalf("error = %+v", out)
			}

			// Server streaming with the trailers frame.
			out = web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + "/ServerStream", "request": map[string]any{"text": "s", "count": 3}}))
			if strings.Join(out.texts(t), ",") != "s-0,s-1,s-2" || out.Status.Code != 0 || out.Kind != "server_streaming" || out.EndedBy != "complete" || out.Trailers["x-echo-trailer"] != "t1" {
				t.Fatalf("stream = %+v", out)
			}
			// Error in the trailers frame after messages.
			out = web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + "/ServerStream", "request": map[string]any{"count": 2, "failCode": 9}}))
			if len(out.Messages) != 2 || out.Status.Name != "FAILED_PRECONDITION" || out.Status.Message != "requested failure: 100% on purpose" || len(out.Status.Details) != 1 {
				t.Fatalf("stream error = %+v", out)
			}
			// Bounded by max_messages / max_duration.
			out = web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + "/ServerStream", "max_messages": 2,
				"request": map[string]any{"text": "e", "count": -1, "delayMs": 10}}))
			if len(out.Messages) != 2 || out.EndedBy != "max_messages" || out.Status.Name != "CANCELLED" {
				t.Fatalf("max_messages = %+v", out)
			}
			ws.waitIdle(t)
			start := time.Now()
			out = web(t, h, "grpcweb_request", args(base, map[string]any{"format": format, "method": svcName + "/ServerStream", "max_duration_seconds": 0.4,
				"request": map[string]any{"text": "e", "count": -1, "delayMs": 50}}))
			if out.EndedBy != "max_duration" || len(out.Messages) == 0 || out.Status.Name != "CANCELLED" || time.Since(start) > 4*time.Second {
				t.Fatalf("max_duration = %+v", out)
			}
			ws.waitIdle(t)
		})
	}

	// Descriptor set source.
	out := web(t, h, "grpcweb_request", map[string]any{"url": ws.URL + "/prefix", "descriptor_sets": []string{ds}, "method": svcName + "/Unary", "request": map[string]any{"text": "ds"}})
	if out.resp(t).Text != "ds" || out.DescriptorSource != "descriptor_set" {
		t.Fatalf("descriptor set = %+v", out)
	}
	// A body cut mid-frame is a failed stream (a result), not OK / CANCELLED.
	out = web(t, h, "grpcweb_request", args(base, map[string]any{"method": svcName + "/ServerStream", "request": map[string]any{"text": "truncate", "count": 1}}))
	if len(out.Messages) != 1 || out.EndedBy != "error" || out.Status.Name != "UNKNOWN" || !strings.Contains(out.Status.Message, "stream failed") {
		t.Fatalf("truncated = %+v", out)
	}
	// HTTP-level failure maps to a status.
	out = web(t, h, "grpcweb_request", args(base, map[string]any{"url": ws.URL + "/other", "method": svcName + "/Unary"}))
	if out.HTTPStatus != 404 || out.Status.Name != "UNIMPLEMENTED" {
		t.Fatalf("404 = %+v", out)
	}
	h.MustFail("grpcweb_request", map[string]any{"url": ws.URL, "method": svcName + "/Unary"}, "proto_files")
	h.MustFail("grpcweb_request", args(base, map[string]any{"method": svcName + "/Bidi"}), "only unary and server-streaming")
	h.MustFail("grpcweb_request", args(base, map[string]any{"method": svcName + "/Unary", "format": "xml"}), "format")
	h.MustFail("grpcweb_request", args(base, map[string]any{"method": svcName + "/Unary", "request": map[string]any{"bogus": 1}}), "does not match")
}

func TestConnect(t *testing.T) {
	cs := startConnect(t)
	h := tooltest.New(t, "grpc")
	p := writeProtos(h)
	base := map[string]any{"url": cs.URL, "proto_files": []string{p}}

	for _, enc := range []string{"json", "proto"} {
		t.Run(enc, func(t *testing.T) {
			out := web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/Unary",
				"request": map[string]any{"text": "hi", "data": b64([]byte{7, 7})}, "metadata": map[string]string{"x-custom": "c"}}))
			r := out.resp(t)
			if out.Status.Code != 0 || out.ConnectCode != "ok" || out.Protocol != "connect+"+enc || r.Text != "hi" || string(r.Data) != "\x07\x07" {
				t.Fatalf("unary = %+v", out)
			}
			if r.Metadata["x-custom"] != "c" || r.Metadata["connect-timeout-ms"] == "" {
				t.Errorf("server saw %v", r.Metadata)
			}
			if out.Headers["x-echo-header"] != "h1" || out.Trailers["x-echo-trailer"] != "t1" {
				t.Errorf("headers=%v trailers=%v", out.Headers, out.Trailers)
			}
			if _, ok := out.Headers["trailer-x-echo-trailer"]; ok {
				t.Errorf("Trailer- header left in headers: %v", out.Headers)
			}
			if got := lastHdr(cs).Get("Content-Type"); got != "application/"+enc {
				t.Errorf("request content type = %s", got)
			}

			// Error response with details.
			out = web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/Unary", "request": map[string]any{"failCode": 5}}))
			if out.HTTPStatus != 404 || out.ConnectCode != "not_found" || out.Status.Code != 5 || out.Status.Message != "requested failure" ||
				len(out.Status.Details) != 1 || out.Status.Details[0]["reason"] != "TEST_FAILURE" || out.Response != nil {
				t.Fatalf("error = %+v", out)
			}

			// Server streaming, end-stream OK and error.
			out = web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/ServerStream", "request": map[string]any{"text": "s", "count": 3}}))
			if strings.Join(out.texts(t), ",") != "s-0,s-1,s-2" || out.Status.Code != 0 || out.Kind != "server_streaming" || out.Trailers["x-echo-trailer"] != "t1" {
				t.Fatalf("stream = %+v", out)
			}
			if got := lastHdr(cs).Get("Content-Type"); got != "application/connect+"+enc {
				t.Errorf("stream request content type = %s", got)
			}
			out = web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/ServerStream", "request": map[string]any{"count": 1, "failCode": 9}}))
			if len(out.Messages) != 1 || out.ConnectCode != "failed_precondition" || out.Status.Code != 9 || len(out.Status.Details) != 1 {
				t.Fatalf("stream error = %+v", out)
			}
			// Cut short by max_messages: not reported as OK.
			out = web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/ServerStream", "max_messages": 2,
				"request": map[string]any{"text": "e", "count": -1, "delayMs": 10}}))
			if len(out.Messages) != 2 || out.EndedBy != "max_messages" || out.Status.Name != "CANCELLED" || out.ConnectCode == "ok" {
				t.Fatalf("max_messages = %+v", out)
			}
			cs.waitIdle(t)
			out = web(t, h, "connect_request", args(base, map[string]any{"encoding": enc, "method": svcName + "/ServerStream", "max_duration_seconds": 0.3,
				"request": map[string]any{"text": "e", "count": -1, "delayMs": 50}}))
			if out.EndedBy != "max_duration" || out.Status.Name != "CANCELLED" || out.ConnectCode == "ok" {
				t.Fatalf("max_duration = %+v", out)
			}
			cs.waitIdle(t)
		})
	}

	out := web(t, h, "connect_request", args(base, map[string]any{"method": svcName + "/ServerStream", "request": map[string]any{"text": "truncate", "count": 1}}))
	if len(out.Messages) != 1 || out.EndedBy != "error" || out.Status.Name != "UNKNOWN" || out.ConnectCode != "unknown" {
		t.Fatalf("truncated = %+v", out)
	}
	// Connection refused is a tool error.
	h.MustFail("connect_request", map[string]any{"url": "http://127.0.0.1:1", "method": svcName + "/ServerStream", "server_streaming": true, "timeout_seconds": 3}, "request failed")
	h.MustFail("grpcweb_request", args(base, map[string]any{"url": "http://127.0.0.1:1", "method": svcName + "/ServerStream", "timeout_seconds": 3}), "request failed")
	// JSON without descriptors: the request is passed through.
	out = web(t, h, "connect_request", map[string]any{"url": cs.URL + "/", "method": svcName + "/Unary", "request": map[string]any{"text": "raw"}})
	if out.resp(t).Text != "raw" || out.DescriptorSource != "" || out.Kind != "unary" {
		t.Fatalf("raw = %+v", out)
	}
	out = web(t, h, "connect_request", map[string]any{"url": cs.URL, "method": svcName + "/ServerStream", "server_streaming": true, "request": `{"text":"r","count":2}`})
	if strings.Join(out.texts(t), ",") != "r-0,r-1" || out.Status.Code != 0 {
		t.Fatalf("raw stream = %+v", out)
	}
	out = web(t, h, "connect_request", map[string]any{"url": cs.URL, "method": svcName + "/Nope"})
	if out.ConnectCode != "unimplemented" || out.Status.Code != 12 {
		t.Fatalf("unimplemented = %+v", out)
	}
	h.MustFail("connect_request", map[string]any{"url": cs.URL, "method": svcName + "/Unary", "encoding": "proto"}, "proto_files")
	h.MustFail("connect_request", map[string]any{"url": cs.URL, "method": svcName + "/Unary", "encoding": "xml"}, "encoding")
	h.MustFail("connect_request", args(base, map[string]any{"method": svcName + "/ClientStream"}), "only unary and server-streaming")
}

func lastHdr(s *webServer) http.Header { return s.last.Load().(http.Header) }

func TestWebSSRFGuard(t *testing.T) {
	gw := startGRPCWeb(t)
	cs := startConnect(t)
	h := tooltest.New(t, "grpc", tooltest.WithPrivateMode(config.PrivateOptIn))
	p := writeProtos(h)
	h.MustFail("grpcweb_request", map[string]any{"url": gw.URL + "/prefix", "proto_files": []string{p}, "method": svcName + "/Unary"}, "blocked")
	h.MustFail("connect_request", map[string]any{"url": cs.URL, "method": svcName + "/Unary"}, "blocked")
	h.MustFail("connect_request", map[string]any{"url": cs.URL, "method": svcName + "/ServerStream", "server_streaming": true}, "blocked")
	h.MustFail("grpcweb_request", map[string]any{"url": gw.URL + "/prefix", "proto_files": []string{p}, "method": svcName + "/ServerStream"}, "blocked")
	out := web(t, h, "grpcweb_request", map[string]any{"url": gw.URL + "/prefix", "proto_files": []string{p}, "method": svcName + "/Unary", "allow_private": true, "request": map[string]any{"text": "ok"}})
	if out.resp(t).Text != "ok" {
		t.Fatalf("allow_private: %+v", out)
	}
	out = web(t, h, "connect_request", map[string]any{"url": cs.URL, "method": svcName + "/Unary", "allow_private": true, "request": map[string]any{"text": "ok"}})
	if out.resp(t).Text != "ok" {
		t.Fatalf("allow_private: %+v", out)
	}
}
