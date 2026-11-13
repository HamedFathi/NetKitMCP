package grpctools_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type statusOut struct {
	Code    int              `json:"code"`
	Name    string           `json:"name"`
	Message string           `json:"message"`
	Details []map[string]any `json:"details"`
}

type unaryResult struct {
	Target           string            `json:"target"`
	Method           string            `json:"method"`
	Status           statusOut         `json:"status"`
	Response         json.RawMessage   `json:"response"`
	Headers          map[string]string `json:"headers"`
	Trailers         map[string]string `json:"trailers"`
	TLS              *types.TLSInfo    `json:"tls"`
	DescriptorSource string            `json:"descriptor_source"`
	Warnings         []string          `json:"warnings"`
}

func (u unaryResult) resp(t *testing.T) echoResp {
	t.Helper()
	var r echoResp
	if len(u.Response) > 0 {
		if err := json.Unmarshal(u.Response, &r); err != nil {
			t.Fatalf("response %s: %v", u.Response, err)
		}
	}
	return r
}

type streamResult struct {
	types.StreamResult
	Kind             string            `json:"kind"`
	Sent             int               `json:"sent"`
	Status           *statusOut        `json:"status"`
	Headers          map[string]string `json:"headers"`
	Trailers         map[string]string `json:"trailers"`
	DescriptorSource string            `json:"descriptor_source"`
	Note             string            `json:"note"`
	Warnings         []string          `json:"warnings"`
}

func (s streamResult) in(t *testing.T) []echoResp {
	t.Helper()
	var out []echoResp
	for _, m := range s.Messages {
		if m.Dir != "in" {
			continue
		}
		var r echoResp
		if err := json.Unmarshal([]byte(m.Data), &r); err != nil {
			t.Fatalf("message %q: %v", m.Data, err)
		}
		out = append(out, r)
	}
	return out
}

func plain(addr string) map[string]any { return map[string]any{"target": addr, "plaintext": true} }

func unary(t *testing.T, h *tooltest.Harness, a map[string]any) unaryResult {
	t.Helper()
	var out unaryResult
	h.MustOK("grpc_unary_request", a).Decode(t, &out)
	return out
}

func stream(t *testing.T, h *tooltest.Harness, a map[string]any) streamResult {
	t.Helper()
	var out streamResult
	h.MustOK("grpc_stream_request", a).Decode(t, &out)
	return out
}

// ---- grpc_describe ----

type describeResult struct {
	Source   string              `json:"source"`
	Services []grpcx.ServiceInfo `json:"services"`
	Symbol   string              `json:"symbol"`
	Kind     string              `json:"kind"`
	Text     string              `json:"text"`
	Service  *grpcx.ServiceInfo  `json:"service"`
	Method   *grpcx.MethodInfo   `json:"method"`
	Message  *grpcx.MessageInfo  `json:"message"`
	Enum     *grpcx.EnumInfo     `json:"enum"`
	Input    *grpcx.MessageInfo  `json:"input"`
	Template map[string]any      `json:"request_template"`
}

func describe(t *testing.T, h *tooltest.Harness, a map[string]any) describeResult {
	t.Helper()
	var out describeResult
	h.MustOK("grpc_describe", a).Decode(t, &out)
	return out
}

func checkEchoService(t *testing.T, services []grpcx.ServiceInfo) {
	t.Helper()
	for _, s := range services {
		if s.Name != svcName {
			continue
		}
		kinds := map[string]string{}
		for _, m := range s.Methods {
			kinds[m.Name] = m.Kind
		}
		want := map[string]string{"Unary": "unary", "ServerStream": "server_streaming", "ClientStream": "client_streaming", "Bidi": "bidi_streaming"}
		for n, k := range want {
			if kinds[n] != k {
				t.Errorf("method %s kind = %q, want %q (all: %v)", n, kinds[n], k, kinds)
			}
		}
		if s.Comment != "Echo is the test service." {
			t.Errorf("service comment = %q", s.Comment)
		}
		return
	}
	t.Fatalf("service %s not listed: %+v", svcName, services)
}

func TestDescribeReflection(t *testing.T) {
	for _, ver := range []string{"v1", "v1alpha"} {
		t.Run(ver, func(t *testing.T) {
			srv := startServer(t, serverOpts{reflection: ver})
			h := tooltest.New(t, "grpc")
			out := describe(t, h, plain(srv.addr))
			if out.Source != "reflection_"+ver {
				t.Errorf("source = %q", out.Source)
			}
			checkEchoService(t, out.Services)
			names := map[string]bool{}
			for _, s := range out.Services {
				names[s.Name] = true
				if s.Error != "" {
					t.Errorf("service %s: %s", s.Name, s.Error)
				}
			}
			if !names["grpc.health.v1.Health"] {
				t.Errorf("health service missing: %v", names)
			}

			// Method (slash and dot forms).
			for _, sym := range []string{svcName + "/Bidi", svcName + ".Bidi"} {
				m := describe(t, h, args(plain(srv.addr), map[string]any{"symbol": sym}))
				if m.Kind != "method" || m.Method == nil || !m.Method.ClientStreaming || !m.Method.ServerStreaming || m.Method.Path != "/"+svcName+"/Bidi" {
					t.Fatalf("%s: %+v", sym, m)
				}
				if m.Input == nil || m.Input.Name != reqName || m.Template == nil {
					t.Fatalf("%s: input/template missing: %+v", sym, m)
				}
				if _, ok := m.Template["delayMs"]; !ok {
					if _, ok := m.Template["delay_ms"]; !ok {
						t.Errorf("template lacks delay field: %v", m.Template)
					}
				}
				if !strings.Contains(m.Text, "rpc Bidi") || !strings.Contains(m.Text, "message netkit.test.v1.EchoRequest {") {
					t.Errorf("text = %s", m.Text)
				}
			}
			// Message.
			m := describe(t, h, args(plain(srv.addr), map[string]any{"symbol": reqName}))
			if m.Kind != "message" || m.Message == nil {
				t.Fatalf("message: %+v", m)
			}
			fields := map[string]grpcx.FieldInfo{}
			for _, f := range m.Message.Fields {
				fields[f.Name] = f
			}
			if fields["data"].Type != "bytes" || fields["labels"].Label != "map" || fields["items"].Label != "repeated" ||
				fields["at"].Type != "google.protobuf.Timestamp" || fields["kind"].Type != "netkit.test.v1.Kind" {
				t.Errorf("fields = %+v", fields)
			}
			// Enum (in an imported file) and service.
			e := describe(t, h, args(plain(srv.addr), map[string]any{"symbol": "netkit.test.v1.Kind"}))
			if e.Kind != "enum" || e.Enum == nil || len(e.Enum.Values) != 2 || e.Enum.Values[1].Name != "KIND_FAST" {
				t.Fatalf("enum: %+v", e)
			}
			s := describe(t, h, args(plain(srv.addr), map[string]any{"symbol": svcName}))
			if s.Kind != "service" || s.Service == nil || len(s.Service.Methods) != 4 {
				t.Fatalf("service: %+v", s)
			}
			h.MustFail("grpc_describe", args(plain(srv.addr), map[string]any{"symbol": "netkit.test.v1.Nope"}), "not found")
			h.MustFail("grpc_describe", args(plain(srv.addr), map[string]any{"symbol": svcName + "/Nope"}), "no method")
		})
	}
}

func TestDescribeNoReflection(t *testing.T) {
	srv := startServer(t, serverOpts{reflection: "none"})
	h := tooltest.New(t, "grpc")
	h.MustFail("grpc_describe", plain(srv.addr), "reflection is not available")
	// proto_files still work with a target.
	p := writeProtos(h)
	out := describe(t, h, args(plain(srv.addr), map[string]any{"proto_files": []string{p}}))
	checkEchoService(t, out.Services)
}

func TestDescribeProtoFilesAndDescriptorSet(t *testing.T) {
	h := tooltest.New(t, "grpc")
	p := writeProtos(h)
	ds := writeDescriptorSet(t, h, compileTestProtos(t))

	cases := []struct {
		name string
		a    map[string]any
		src  string
	}{
		{"file", map[string]any{"proto_files": []string{p}}, "proto_files"},
		{"dir", map[string]any{"proto_files": []string{h.ReadDir}}, "proto_files"},
		{"import_path", map[string]any{"proto_files": []string{"echo.proto"}, "import_paths": []string{h.ReadDir}}, "proto_files"},
		{"descriptor_set", map[string]any{"descriptor_sets": []string{ds}}, "descriptor_set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := describe(t, h, c.a)
			if out.Source != c.src {
				t.Errorf("source = %q", out.Source)
			}
			checkEchoService(t, out.Services)
			m := describe(t, h, args(c.a, map[string]any{"symbol": svcName + "/Unary"}))
			if m.Method == nil || m.Method.Kind != "unary" {
				t.Fatalf("method: %+v", m)
			}
			if c.src == "proto_files" && m.Method.Comment != "Unary echoes one request." {
				t.Errorf("comment = %q", m.Method.Comment)
			}
			msg := describe(t, h, args(c.a, map[string]any{"symbol": "netkit.test.v1.Item"}))
			if msg.Message == nil || len(msg.Message.Fields) != 2 {
				t.Fatalf("Item: %+v", msg)
			}
		})
	}

	h.MustFail("grpc_describe", map[string]any{}, "target")
	// Paths outside the allowed dirs are refused.
	outside := filepath.Join(t.TempDir(), "x.proto")
	h.MustFail("grpc_describe", map[string]any{"proto_files": []string{outside}}, "")
	bad := h.WriteInput("bad.proto", []byte("syntax = \"proto3\"; message {"))
	h.MustFail("grpc_describe", map[string]any{"proto_files": []string{bad}}, "compile")
	notSet := h.WriteInput("garbage.pb", []byte("not a descriptor set"))
	h.MustFail("grpc_describe", map[string]any{"descriptor_sets": []string{notSet}}, "FileDescriptorSet")
}

// ---- grpc_unary_request ----

func TestUnaryAllSources(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	p := writeProtos(h)
	ds := writeDescriptorSet(t, h, srv.env.reg)
	for name, extra := range map[string]map[string]any{
		"reflection":     {},
		"proto_files":    {"proto_files": []string{p}},
		"descriptor_set": {"descriptor_sets": []string{ds}},
	} {
		t.Run(name, func(t *testing.T) {
			out := unary(t, h, args(plain(srv.addr), extra, map[string]any{
				"method": svcName + "/Unary",
				"request": map[string]any{
					"text": "hi", "kind": "KIND_FAST", "at": "2026-01-02T03:04:05Z",
					"labels": map[string]any{"a": "b"},
				},
				"metadata": map[string]string{"x-custom": "v1", "X-Upper": "up", "x-token-bin": b64([]byte{9, 8, 7})},
			}))
			if out.Status.Code != 0 || out.Status.Name != "OK" {
				t.Fatalf("status = %+v", out.Status)
			}
			r := out.resp(t)
			if r.Text != "hi" || r.At != "2026-01-02T03:04:05Z" || r.Received != 1 {
				t.Errorf("response = %s", out.Response)
			}
			if r.Metadata["x-custom"] != "v1" || r.Metadata["x-upper"] != "up" || r.Metadata["x-token-bin"] != b64([]byte{9, 8, 7}) {
				t.Errorf("server saw metadata %v", r.Metadata)
			}
			if out.Headers["x-echo-header"] != "h1" {
				t.Errorf("headers = %v", out.Headers)
			}
			if out.Trailers["x-echo-trailer"] != "t1" || out.Trailers["x-trace-bin"] != b64([]byte{0, 1, 2, 255}) {
				t.Errorf("trailers = %v", out.Trailers)
			}
			if out.Method != "/"+svcName+"/Unary" {
				t.Errorf("method = %q", out.Method)
			}
			if !strings.HasPrefix(out.DescriptorSource, strings.Split(name, "_")[0]) {
				t.Errorf("descriptor_source = %q", out.DescriptorSource)
			}
			if out.TLS != nil {
				t.Errorf("plaintext call reported TLS %+v", out.TLS)
			}
		})
	}
}

func TestUnaryErrorsAndOptions(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	base := args(plain(srv.addr), map[string]any{"method": svcName + "/Unary"})

	// A non-OK status is a result, with decoded details and trailers.
	out := unary(t, h, args(base, map[string]any{"request": map[string]any{"failCode": 5}}))
	if out.Status.Code != 5 || out.Status.Name != "NOT_FOUND" || out.Status.Message != "requested failure: 100% on purpose" {
		t.Fatalf("status = %+v", out.Status)
	}
	if len(out.Status.Details) != 1 || out.Status.Details[0]["@type"] != "type.googleapis.com/google.rpc.ErrorInfo" || out.Status.Details[0]["reason"] != "TEST_FAILURE" {
		t.Errorf("details = %+v", out.Status.Details)
	}
	if out.Response != nil && string(out.Response) != "null" {
		t.Errorf("response on error = %s", out.Response)
	}
	if out.Trailers["x-echo-trailer"] != "t1" {
		t.Errorf("trailers on error = %v", out.Trailers)
	}

	// Deadline: the server sleeps longer than timeout_seconds.
	start := time.Now()
	out = unary(t, h, args(base, map[string]any{"request": map[string]any{"delayMs": 5000}, "timeout_seconds": 0.5}))
	if out.Status.Name != "DEADLINE_EXCEEDED" {
		t.Errorf("status = %+v", out.Status)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("deadline call took %v", el)
	}

	// Response JSON options.
	out = unary(t, h, args(base, map[string]any{"request": `{"text":"s"}`, "emit_defaults": true, "use_proto_names": true}))
	var raw map[string]any
	json.Unmarshal(out.Response, &raw)
	if _, ok := raw["received"]; !ok {
		t.Errorf("emit_defaults: %s", out.Response)
	}
	if _, ok := raw["index"]; !ok || raw["text"] != "s" {
		t.Errorf("emit_defaults/use_proto_names: %s", out.Response)
	}

	// Tool errors: bad request, unknown field, streaming method, bad method name.
	h.MustFail("grpc_unary_request", args(base, map[string]any{"request": map[string]any{"nope": 1}}), "does not match")
	h.MustFail("grpc_unary_request", args(base, map[string]any{"request": "{not json"}), "JSON")
	h.MustFail("grpc_unary_request", args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi"}), "grpc_stream_request")
	h.MustFail("grpc_unary_request", args(plain(srv.addr), map[string]any{"method": "Nope"}), "package.Service/Method")
	h.MustFail("grpc_unary_request", args(plain(srv.addr), map[string]any{"method": "netkit.test.v1.Missing/Unary"}), "not found")
	h.MustFail("grpc_unary_request", args(base, map[string]any{"metadata": map[string]string{"k-bin": "!!"}}), "base64")
	// Unreachable server: a status result or a tool error, never a hang.
	closed := "127.0.0.1:1"
	start = time.Now()
	r := h.Call("grpc_unary_request", args(plain(closed), map[string]any{"method": svcName + "/Unary", "timeout_seconds": 2}))
	if !r.IsError {
		var u unaryResult
		r.Decode(t, &u)
		if u.Status.Code == 0 {
			t.Errorf("unreachable server returned OK")
		}
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("unreachable call took %v", time.Since(start))
	}
}

func TestUnaryBytesFields(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	base := args(plain(srv.addr), map[string]any{"method": svcName + "/Unary"})
	bin := []byte{0, 1, 2, 0xfe, 0xff, 'x'}

	// base64 (std and raw URL alphabets).
	out := unary(t, h, args(base, map[string]any{"request": map[string]any{"data": b64(bin)}}))
	if r := out.resp(t); string(r.Data) != string(bin) {
		t.Errorf("base64 data echoed as %v", r.Data)
	}

	// {"$file": path}, top-level and nested in a repeated message.
	big := make([]byte, 70000)
	for i := range big {
		big[i] = byte(i * 7)
	}
	p := h.WriteInput("blob.bin", big)
	q := h.WriteInput("small.bin", bin)
	out = unary(t, h, args(base, map[string]any{"request": map[string]any{
		"data":  map[string]any{"$file": p},
		"items": []any{map[string]any{"name": "a", "blob": map[string]any{"$file": q}}, map[string]any{"name": "b", "blob": b64([]byte("zz"))}},
	}}))
	r := out.resp(t)
	if string(r.Data) != string(big) {
		t.Errorf("$file data: got %d bytes", len(r.Data))
	}
	if len(r.Items) != 2 || string(r.Items[0].Blob) != string(bin) || string(r.Items[1].Blob) != "zz" {
		t.Errorf("items = %+v", r.Items)
	}
	// Response bytes come back base64 in the JSON.
	var raw map[string]any
	json.Unmarshal(out.Response, &raw)
	if s, _ := raw["data"].(string); s != b64(big) {
		t.Errorf("response data is not base64")
	}

	outside := filepath.Join(t.TempDir(), "secret.bin")
	h.MustFail("grpc_unary_request", args(base, map[string]any{"request": map[string]any{"data": map[string]any{"$file": outside}}}), "$file")
	h.MustFail("grpc_unary_request", args(base, map[string]any{"request": map[string]any{"data": map[string]any{"$file": p, "x": 1}}}), "$file")
	h.MustFail("grpc_unary_request", args(base, map[string]any{"request": map[string]any{"data": "%%%"}}), "")
}

// ---- grpc_stream_request ----

func TestStreamRequestModes(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	p := writeProtos(h)
	base := plain(srv.addr)

	t.Run("server_streaming", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "messages": []any{map[string]any{"text": "s", "count": 3}}}))
		in := out.in(t)
		if out.Kind != "server_streaming" || out.Sent != 1 || len(in) != 3 || in[2].Text != "s-2" || in[2].Index != 2 {
			t.Fatalf("out = %+v", out)
		}
		if out.EndedBy != "complete" || out.Status == nil || out.Status.Code != 0 {
			t.Errorf("ended_by=%q status=%+v", out.EndedBy, out.Status)
		}
		if out.Headers["x-echo-header"] != "h1" || out.Trailers["x-echo-trailer"] != "t1" {
			t.Errorf("headers=%v trailers=%v", out.Headers, out.Trailers)
		}
		if out.Messages[0].Dir != "out" || out.Messages[0].Seq != 1 {
			t.Errorf("first message = %+v", out.Messages[0])
		}
	})
	t.Run("server_streaming_error", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "messages": []any{map[string]any{"count": 2, "failCode": 9}}}))
		if len(out.in(t)) != 2 || out.Status == nil || out.Status.Name != "FAILED_PRECONDITION" || len(out.Status.Details) != 1 {
			t.Fatalf("out = %+v", out)
		}
	})
	t.Run("client_streaming", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ClientStream", "proto_files": []string{p},
			"messages": []any{map[string]any{"text": "a"}, map[string]any{"text": "b"}, map[string]any{"text": "c"}}}))
		in := out.in(t)
		if out.Kind != "client_streaming" || out.Sent != 3 || len(in) != 1 || in[0].Text != "a,b,c" || in[0].Received != 3 {
			t.Fatalf("out = %+v", out)
		}
		if out.Status == nil || out.Status.Code != 0 || out.DescriptorSource != "proto_files" || out.Trailers["x-echo-trailer"] != "t1" {
			t.Errorf("out = %+v", out)
		}
	})
	t.Run("client_streaming_empty", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ClientStream"}))
		if in := out.in(t); out.Sent != 0 || len(in) != 1 || in[0].Received != 0 {
			t.Fatalf("out = %+v", out)
		}
	})
	t.Run("bidi", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/Bidi",
			"messages": []any{map[string]any{"text": "x"}, map[string]any{"text": "y", "data": b64([]byte{1, 2})}}}))
		in := out.in(t)
		if out.Kind != "bidi_streaming" || out.Sent != 2 || len(in) != 2 || in[0].Text != "echo:x" || in[1].Text != "echo:y" || string(in[1].Data) != "\x01\x02" {
			t.Fatalf("out = %+v", out)
		}
		if out.Status == nil || out.Status.Code != 0 || out.EndedBy != "complete" {
			t.Errorf("status = %+v ended_by=%s", out.Status, out.EndedBy)
		}
	})
	t.Run("unary_via_stream", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/Unary", "messages": []any{map[string]any{"text": "u"}}}))
		if in := out.in(t); out.Kind != "unary" || len(in) != 1 || in[0].Text != "u" {
			t.Fatalf("out = %+v", out)
		}
	})
	t.Run("max_messages", func(t *testing.T) {
		start := time.Now()
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "max_messages": 3,
			"messages": []any{map[string]any{"text": "m", "count": -1, "delayMs": 10}}}))
		if out.EndedBy != "max_messages" || len(out.in(t)) != 3 || out.Status != nil || out.Note == "" {
			t.Fatalf("out = %+v", out)
		}
		if time.Since(start) > 4*time.Second {
			t.Errorf("took %v", time.Since(start))
		}
		srv.env.waitIdle(t)
	})
	t.Run("max_duration", func(t *testing.T) {
		start := time.Now()
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "max_duration_seconds": 0.5,
			"messages": []any{map[string]any{"text": "d", "count": -1, "delayMs": 50}}}))
		el := time.Since(start)
		n := len(out.in(t))
		if out.EndedBy != "max_duration" || n < 2 || n > 40 || out.Status != nil {
			t.Fatalf("ended_by=%s n=%d status=%+v", out.EndedBy, n, out.Status)
		}
		if el < 400*time.Millisecond || el > 4*time.Second {
			t.Errorf("took %v", el)
		}
		srv.env.waitIdle(t)
	})
	t.Run("idle_timeout", func(t *testing.T) {
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "idle_timeout_seconds": 0.3,
			"messages": []any{map[string]any{"count": 2, "delayMs": 3000}}}))
		if out.EndedBy != "idle" || len(out.in(t)) != 1 {
			t.Fatalf("out = %+v", out)
		}
		srv.env.waitIdle(t)
	})
	t.Run("bidi_bounded_by_duration", func(t *testing.T) {
		// A bidi stream whose server never finishes: the client half-closes,
		// but ClientStream-like servers that wait forever must still end.
		out := stream(t, h, args(base, map[string]any{"method": svcName + "/ServerStream", "max_duration_seconds": 0.3,
			"messages": []any{map[string]any{"count": 1, "delayMs": 10000}}}))
		if out.EndedBy != "max_duration" {
			t.Fatalf("out = %+v", out)
		}
		srv.env.waitIdle(t)
	})
	t.Run("errors", func(t *testing.T) {
		h.MustFail("grpc_stream_request", args(base, map[string]any{"method": svcName + "/ServerStream", "messages": []any{map[string]any{}, map[string]any{}}}), "exactly one")
		h.MustFail("grpc_stream_request", args(base, map[string]any{"method": svcName + "/Bidi", "messages": []any{map[string]any{"bogus": true}}}), "messages[0]")
	})
}

// ---- interactive sessions ----

type openResult struct {
	SessionID  string           `json:"session_id"`
	Method     grpcx.MethodInfo `json:"method"`
	Sent       int              `json:"sent"`
	SendClosed bool             `json:"send_closed"`
	Warnings   []string         `json:"warnings"`
}

type recvResult struct {
	types.StreamResult
	Ended    bool              `json:"stream_ended"`
	Status   *statusOut        `json:"status"`
	Headers  map[string]string `json:"headers"`
	Trailers map[string]string `json:"trailers"`
}

type closeResult struct {
	Status    statusOut             `json:"status"`
	Cancelled bool                  `json:"cancelled_by_client"`
	Remaining []types.StreamMessage `json:"remaining_messages"`
	Headers   map[string]string     `json:"headers"`
	Trailers  map[string]string     `json:"trailers"`
	TotalSent int                   `json:"total_sent"`
}

func open(t *testing.T, h *tooltest.Harness, a map[string]any) openResult {
	t.Helper()
	var o openResult
	h.MustOK("grpc_stream_open", a).Decode(t, &o)
	if !strings.HasPrefix(o.SessionID, "grpc_stream_") {
		t.Fatalf("session id = %q", o.SessionID)
	}
	return o
}

func recv(t *testing.T, h *tooltest.Harness, id string, a map[string]any) recvResult {
	t.Helper()
	var r recvResult
	h.MustOK("grpc_stream_recv", args(map[string]any{"session_id": id}, a)).Decode(t, &r)
	return r
}

func closeSession(t *testing.T, h *tooltest.Harness, id string, a map[string]any) closeResult {
	t.Helper()
	var c closeResult
	h.MustOK("grpc_stream_close", args(map[string]any{"session_id": id}, a)).Decode(t, &c)
	return c
}

func texts(t *testing.T, msgs []types.StreamMessage) []string {
	t.Helper()
	var out []string
	for _, m := range msgs {
		out = append(out, mustJSON(t, m.Data)["text"].(string))
	}
	return out
}

func TestStreamSessionBidiLifecycle(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	o := open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi", "messages": []any{map[string]any{"text": "one"}}}))
	if o.Sent != 1 || o.SendClosed || o.Method.Kind != "bidi_streaming" {
		t.Fatalf("open = %+v", o)
	}
	var sent struct {
		Sent       int  `json:"sent"`
		TotalSent  int  `json:"total_sent"`
		SendClosed bool `json:"send_closed"`
	}
	h.MustOK("grpc_stream_send", map[string]any{"session_id": o.SessionID, "messages": []any{map[string]any{"text": "two"}, map[string]any{"text": "three"}}}).Decode(t, &sent)
	if sent.Sent != 2 || sent.TotalSent != 3 || sent.SendClosed {
		t.Fatalf("send = %+v", sent)
	}
	var got []string
	deadline := time.Now().Add(5 * time.Second)
	var hdr map[string]string
	for len(got) < 3 && time.Now().Before(deadline) {
		r := recv(t, h, o.SessionID, map[string]any{"wait_seconds": 2})
		got = append(got, texts(t, r.Messages)...)
		if r.Ended {
			t.Fatalf("ended early: %+v", r)
		}
		hdr = r.Headers
	}
	if strings.Join(got, "|") != "echo:one|echo:two|echo:three" {
		t.Fatalf("received %v", got)
	}
	if hdr["x-echo-header"] != "h1" {
		t.Errorf("headers = %v", hdr)
	}
	// Nothing pending: a short wait returns empty.
	start := time.Now()
	r := recv(t, h, o.SessionID, map[string]any{"wait_seconds": 0.2})
	if len(r.Messages) != 0 || r.Ended || time.Since(start) > 2*time.Second {
		t.Fatalf("idle recv = %+v", r)
	}
	// Half-close: the server finishes, recv reports the final status.
	h.MustOK("grpc_stream_send", map[string]any{"session_id": o.SessionID, "close_send": true}).Decode(t, &sent)
	if !sent.SendClosed {
		t.Fatalf("send close = %+v", sent)
	}
	h.MustFail("grpc_stream_send", map[string]any{"session_id": o.SessionID, "messages": []any{map[string]any{}}}, "already closed")
	h.MustFail("grpc_stream_send", map[string]any{"session_id": o.SessionID}, "nothing to do")
	r = recv(t, h, o.SessionID, map[string]any{"wait_seconds": 3})
	if !r.Ended || r.Status == nil || r.Status.Code != 0 || r.Trailers["x-echo-trailer"] != "t1" {
		t.Fatalf("final recv = %+v", r)
	}
	c := closeSession(t, h, o.SessionID, nil)
	if c.Status.Code != 0 || c.Cancelled || c.TotalSent != 3 || len(c.Remaining) != 0 || c.Trailers["x-echo-trailer"] != "t1" {
		t.Fatalf("close = %+v", c)
	}
	// The session is gone.
	h.MustFail("grpc_stream_recv", map[string]any{"session_id": o.SessionID}, "not found")
	h.MustFail("grpc_stream_send", map[string]any{"session_id": o.SessionID, "close_send": true}, "not found")
	h.MustFail("grpc_stream_close", map[string]any{"session_id": o.SessionID}, "not found")
	h.MustFail("grpc_stream_recv", map[string]any{"session_id": "grpc_stream_deadbeef"}, "not found")
	srv.env.waitIdle(t)
}

func TestStreamSessionCancelAndClientStream(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")

	// Endless server stream: recv some, then close cancels it.
	o := open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/ServerStream",
		"messages": []any{map[string]any{"text": "e", "count": -1, "delayMs": 20}}}))
	if !o.SendClosed {
		t.Errorf("server-streaming open should half-close after its one message: %+v", o)
	}
	// recv returns as soon as something is buffered; poll until 2 arrived.
	var r recvResult
	var got []string
	for i := 0; i < 20 && len(got) < 2; i++ {
		r = recv(t, h, o.SessionID, map[string]any{"max_messages": 2 - len(got), "wait_seconds": 3})
		got = append(got, texts(t, r.Messages)...)
	}
	if strings.Join(got, ",") != "e-0,e-1" || r.EndedBy != "max_messages" {
		t.Fatalf("recv = %v %+v", got, r)
	}
	if srv.env.active.Load() != 1 {
		t.Errorf("active server streams = %d", srv.env.active.Load())
	}
	start := time.Now()
	c := closeSession(t, h, o.SessionID, map[string]any{"wait_seconds": 0.2})
	if !c.Cancelled || c.Status.Name != "CANCELLED" {
		t.Errorf("close = %+v", c)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("close took %v", time.Since(start))
	}
	srv.env.waitIdle(t)

	// Client stream: open without messages, send, close collects the reply.
	o = open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/ClientStream"}))
	h.MustOK("grpc_stream_send", map[string]any{"session_id": o.SessionID, "messages": []any{map[string]any{"text": "a"}, map[string]any{"text": "b"}}})
	c = closeSession(t, h, o.SessionID, map[string]any{"wait_seconds": 3})
	if c.Status.Code != 0 || c.Cancelled || len(c.Remaining) != 1 || c.TotalSent != 2 {
		t.Fatalf("close = %+v", c)
	}
	if got := texts(t, c.Remaining); got[0] != "a,b" {
		t.Errorf("reply = %v", got)
	}

	// Server-side error ends the session with a status.
	o = open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi", "messages": []any{map[string]any{"failCode": 7}}}))
	r = recv(t, h, o.SessionID, map[string]any{"wait_seconds": 3})
	if !r.Ended || r.Status == nil || r.Status.Name != "PERMISSION_DENIED" || r.EndedBy != "error" {
		t.Fatalf("recv = %+v", r)
	}
	h.MustFail("grpc_stream_send", map[string]any{"session_id": o.SessionID, "messages": []any{map[string]any{}}}, "")
	closeSession(t, h, o.SessionID, nil)

	// Sessions left open are closed by the registry (harness cleanup) and
	// must not leave the server handler running.
	o = open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi"}))
	if err := h.Deps.Sessions.Close(o.SessionID); err != nil {
		t.Fatal(err)
	}
	srv.env.waitIdle(t)

	// Unreachable target (descriptors from files): fails, does not hang.
	p := writeProtos(h)
	start = time.Now()
	h.MustFail("grpc_stream_open", args(plain("127.0.0.1:1"), map[string]any{"method": svcName + "/Bidi", "proto_files": []string{p}, "timeout_seconds": 3}), "")
	if time.Since(start) > 10*time.Second {
		t.Errorf("open on unreachable target took %v", time.Since(start))
	}
	if n := len(h.Deps.Sessions.List("grpc_stream")); n != 0 {
		t.Errorf("%d sessions leaked", n)
	}
	h.MustFail("grpc_stream_open", args(plain(srv.addr), map[string]any{"method": svcName + "/ServerStream", "messages": []any{map[string]any{}, map[string]any{}}}), "exactly one")
	h.MustFail("grpc_stream_open", args(plain(srv.addr), map[string]any{"method": svcName + "/Nope"}), "no method")
}

// A server that stops reading must not make grpc_stream_send hang.
func TestStreamSessionSendBlocked(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	o := open(t, h, args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi", "messages": []any{map[string]any{"text": "stall", "delayMs": 60000}}}))
	blob := make([]byte, 1<<20)
	p := h.WriteInput("mb.bin", blob)
	msgs := make([]any, 48)
	for i := range msgs {
		msgs[i] = map[string]any{"data": map[string]any{"$file": p}}
	}
	start := time.Now()
	h.MustFail("grpc_stream_send", map[string]any{"session_id": o.SessionID, "messages": msgs, "timeout_seconds": 1}, "timed out")
	if el := time.Since(start); el > 15*time.Second {
		t.Errorf("blocked send took %v", el)
	}
	c := closeSession(t, h, o.SessionID, nil)
	if !c.Cancelled {
		t.Errorf("close = %+v", c)
	}
	srv.env.waitIdle(t)
}

// ---- grpc_health_check ----

type healthResult struct {
	ServingStatus string              `json:"serving_status"`
	Status        *statusOut          `json:"status"`
	Watch         *types.StreamResult `json:"watch"`
	Warnings      []string            `json:"warnings"`
}

func TestHealth(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc")
	var out healthResult
	h.MustOK("grpc_health_check", plain(srv.addr)).Decode(t, &out)
	if out.ServingStatus != "SERVING" || out.Status == nil || out.Status.Code != 0 {
		t.Fatalf("overall = %+v", out)
	}
	h.MustOK("grpc_health_check", args(plain(srv.addr), map[string]any{"service": svcName})).Decode(t, &out)
	if out.ServingStatus != "SERVING" {
		t.Fatalf("service = %+v", out)
	}
	out = healthResult{}
	h.MustOK("grpc_health_check", args(plain(srv.addr), map[string]any{"service": "nope.Svc"})).Decode(t, &out)
	if out.Status == nil || out.Status.Name != "NOT_FOUND" || out.ServingStatus != "" {
		t.Fatalf("unknown service = %+v", out)
	}

	// Watch: the first update is the current status, then a change.
	go func() {
		time.Sleep(300 * time.Millisecond)
		srv.health.SetServingStatus(svcName, healthpb.HealthCheckResponse_NOT_SERVING)
	}()
	out = healthResult{}
	h.MustOK("grpc_health_check", args(plain(srv.addr), map[string]any{"service": svcName, "watch": true, "max_messages": 2, "max_duration_seconds": 5})).Decode(t, &out)
	if out.Watch == nil || len(out.Watch.Messages) != 2 || out.Watch.EndedBy != "max_messages" || out.ServingStatus != "NOT_SERVING" {
		t.Fatalf("watch = %+v", out)
	}
	if mustJSON(t, out.Watch.Messages[0].Data)["status"] != "SERVING" {
		t.Errorf("first watch update = %s", out.Watch.Messages[0].Data)
	}
	// Watch bounded by duration on an unknown service (SERVICE_UNKNOWN, then nothing).
	start := time.Now()
	out = healthResult{}
	h.MustOK("grpc_health_check", args(plain(srv.addr), map[string]any{"service": "nope.Svc", "watch": true, "max_messages": 5, "max_duration_seconds": 0.4})).Decode(t, &out)
	if out.Watch == nil || out.Watch.EndedBy != "max_duration" || out.ServingStatus != "SERVICE_UNKNOWN" || time.Since(start) > 4*time.Second {
		t.Fatalf("watch unknown = %+v (%v)", out, time.Since(start))
	}
}

// ---- TLS ----

func TestTLS(t *testing.T) {
	cert, certPEM := selfSigned(t)
	srv := startServer(t, serverOpts{cert: &cert})
	h := tooltest.New(t, "grpc")
	method := map[string]any{"method": svcName + "/Unary", "request": map[string]any{"text": "tls"}}

	// Verified with ca_cert (inline PEM and file path).
	caPath := h.WriteInput("ca.pem", []byte(certPEM))
	for _, ca := range []string{certPEM, caPath} {
		out := unary(t, h, args(method, map[string]any{"target": srv.addr, "ca_cert": ca}))
		if out.Status.Code != 0 || out.resp(t).Text != "tls" {
			t.Fatalf("status = %+v", out.Status)
		}
		if out.TLS == nil || out.TLS.Version == "" || out.TLS.InsecureSkipVerify || len(out.Warnings) != 0 {
			t.Errorf("tls = %+v warnings = %v", out.TLS, out.Warnings)
		}
	}
	// grpcs:// scheme.
	unary(t, h, args(method, map[string]any{"target": "grpcs://" + srv.addr, "ca_cert": certPEM}))

	// insecure_skip_verify works and is flagged.
	out := unary(t, h, args(method, map[string]any{"target": srv.addr, "insecure_skip_verify": true}))
	if out.Status.Code != 0 || out.TLS == nil || !out.TLS.InsecureSkipVerify || len(out.Warnings) == 0 || !strings.Contains(out.Warnings[0], "insecure_skip_verify") {
		t.Errorf("insecure: tls=%+v warnings=%v", out.TLS, out.Warnings)
	}
	var d struct {
		Warnings []string `json:"warnings"`
	}
	h.MustOK("grpc_describe", map[string]any{"target": srv.addr, "insecure_skip_verify": true}).Decode(t, &d)
	if len(d.Warnings) == 0 {
		t.Errorf("describe did not flag insecure_skip_verify")
	}
	var hr healthResult
	h.MustOK("grpc_health_check", map[string]any{"target": srv.addr, "insecure_skip_verify": true}).Decode(t, &hr)
	if len(hr.Warnings) == 0 || hr.ServingStatus != "SERVING" {
		t.Errorf("health insecure = %+v", hr)
	}
	o := open(t, h, map[string]any{"target": srv.addr, "insecure_skip_verify": true, "method": svcName + "/Bidi"})
	if len(o.Warnings) == 0 {
		t.Errorf("stream_open did not flag insecure_skip_verify")
	}
	closeSession(t, h, o.SessionID, nil)
	var sr streamResult
	h.MustOK("grpc_stream_request", map[string]any{"target": srv.addr, "insecure_skip_verify": true, "method": svcName + "/Bidi"}).Decode(t, &sr)
	if len(sr.Warnings) == 0 {
		t.Errorf("stream_request did not flag insecure_skip_verify")
	}

	// Unverified certificate: a tool error or an UNAVAILABLE status, not success.
	p := writeProtos(h)
	r := h.Call("grpc_unary_request", args(method, map[string]any{"target": srv.addr, "proto_files": []string{p}, "timeout_seconds": 5}))
	if !r.IsError {
		var u unaryResult
		r.Decode(t, &u)
		if u.Status.Code != 14 {
			t.Errorf("untrusted cert: status = %+v", u.Status)
		}
	}
	h.MustFail("grpc_unary_request", args(method, map[string]any{"target": srv.addr}), "")
	// Plaintext against TLS options is rejected.
	h.MustFail("grpc_unary_request", args(method, map[string]any{"target": srv.addr, "plaintext": true, "ca_cert": certPEM}), "plaintext")
}

// ---- SSRF guard ----

func TestSSRFGuard(t *testing.T) {
	srv := startServer(t, serverOpts{})
	h := tooltest.New(t, "grpc", tooltest.WithPrivateMode(config.PrivateOptIn))
	m := svcName + "/Unary"
	calls := []struct {
		tool string
		a    map[string]any
	}{
		{"grpc_describe", plain(srv.addr)},
		{"grpc_unary_request", args(plain(srv.addr), map[string]any{"method": m})},
		{"grpc_unary_request", args(plain("localhost:"+strings.Split(srv.addr, ":")[1]), map[string]any{"method": m})},
		{"grpc_stream_request", args(plain(srv.addr), map[string]any{"method": svcName + "/ServerStream"})},
		{"grpc_stream_open", args(plain(srv.addr), map[string]any{"method": svcName + "/Bidi"})},
		{"grpc_health_check", plain(srv.addr)},
		{"grpc_health_check", args(plain(srv.addr), map[string]any{"watch": true})},
		{"grpc_describe", args(plain(srv.addr), map[string]any{"symbol": svcName})},
	}
	for _, c := range calls {
		h.MustFail(c.tool, c.a, "blocked")
	}
	// Opting in works.
	out := unary(t, h, args(plain(srv.addr), map[string]any{"method": m, "allow_private": true, "request": map[string]any{"text": "ok"}}))
	if out.resp(t).Text != "ok" {
		t.Fatalf("allow_private: %+v", out)
	}
	var hr healthResult
	h.MustOK("grpc_health_check", args(plain(srv.addr), map[string]any{"allow_private": true})).Decode(t, &hr)

	// proto_files with a private target is still guarded.
	p := writeProtos(h)
	h.MustFail("grpc_unary_request", args(plain(srv.addr), map[string]any{"method": m, "proto_files": []string{p}}), "blocked")

	// Deny mode ignores allow_private.
	hd := tooltest.New(t, "grpc", tooltest.WithPrivateMode(config.PrivateDeny))
	hd.MustFail("grpc_unary_request", args(plain(srv.addr), map[string]any{"method": m, "allow_private": true}), "blocked")
}
