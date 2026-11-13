package grpcx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in        string
		plain     bool
		want      string
		wantPlain bool
	}{
		{"localhost:50051", false, "localhost:50051", false},
		{"localhost:50051", true, "localhost:50051", true},
		{"grpc://h:1", false, "h:1", true},
		{"grpcs://h:1", true, "h:1", false},
		{"https://h/some/path", true, "h:443", false},
		{"http://h", false, "h:80", true},
		{"dns:///h:9", false, "h:9", false},
		{"passthrough:///h:9", false, "h:9", false},
		{"[::1]:8080", false, "[::1]:8080", false},
		{"::1", false, "[::1]:443", false},
		{"h", false, "h:443", false},
	}
	for _, c := range cases {
		got, plain, err := ParseTarget(c.in, c.plain)
		if err != nil || got != c.want || plain != c.wantPlain {
			t.Errorf("ParseTarget(%q, %v) = %q, %v, %v; want %q, %v", c.in, c.plain, got, plain, err, c.want, c.wantPlain)
		}
	}
	for _, bad := range []string{"", "  ", "grpc://"} {
		if _, _, err := ParseTarget(bad, false); err == nil {
			t.Errorf("ParseTarget(%q) accepted", bad)
		}
	}
}

func TestParseMethodName(t *testing.T) {
	for in, want := range map[string]string{
		"pkg.Svc/M": "pkg.Svc|M", "/pkg.Svc/M": "pkg.Svc|M", "pkg.Svc.M": "pkg.Svc|M", " a.b.C/D ": "a.b.C|D",
	} {
		s, m, err := ParseMethodName(in)
		if err != nil || s+"|"+m != want {
			t.Errorf("ParseMethodName(%q) = %q %q %v", in, s, m, err)
		}
	}
	for _, bad := range []string{"", "M", "pkg.Svc/", "/M"} {
		if _, _, err := ParseMethodName(bad); err == nil {
			t.Errorf("ParseMethodName(%q) accepted", bad)
		}
	}
}

func TestMetadata(t *testing.T) {
	md, err := OutgoingMD(map[string]string{"X-A": "1", "k-bin": base64.StdEncoding.EncodeToString([]byte{0, 255}), " ": "skip"},
		http.Header{"Authorization": {"Bearer secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if md.Get("x-a")[0] != "1" || md.Get("k-bin")[0] != "\x00\xff" || md.Get("authorization")[0] != "Bearer secret" || len(md) != 3 {
		t.Fatalf("md = %v", md)
	}
	if _, err := OutgoingMD(map[string]string{"k-bin": "!!"}, nil); err == nil {
		t.Fatal("bad -bin accepted")
	}
	m := MDToMap(metadata.MD{"k-bin": {"\x00\xff"}, "multi": {"a", "b"}, "authorization": {"Bearer secret-token-value"}})
	if m["k-bin"] != "AP8=" || m["multi"] != "a, b" || strings.Contains(m["authorization"], "secret-token-value") {
		t.Fatalf("map = %v", m)
	}
	h := HeaderToMap(http.Header{"X-Y": {"1"}, "Cookie": {"session=abcdefgh123"}})
	if h["x-y"] != "1" || strings.Contains(h["cookie"], "abcdefgh123") {
		t.Fatalf("header map = %v", h)
	}
}

func TestStatus(t *testing.T) {
	if s := StatusFromError(nil, nil); s.Code != 0 || s.Name != "OK" || !s.OK() {
		t.Fatalf("nil = %+v", s)
	}
	st, _ := status.New(codes.NotFound, "gone").WithDetails(&errdetails.ErrorInfo{Reason: "R"})
	s := StatusFromError(st.Err(), nil)
	if s.Code != 5 || s.Name != "NOT_FOUND" || s.Message != "gone" || len(s.Details) != 1 {
		t.Fatalf("status = %+v", s)
	}
	if d := s.Details[0].(map[string]any); d["reason"] != "R" || d["@type"] != "type.googleapis.com/google.rpc.ErrorInfo" {
		t.Fatalf("detail = %v", d)
	}
	if s := StatusFromError(fmt.Errorf("wrap: %w", context.DeadlineExceeded), nil); s.Name != "DEADLINE_EXCEEDED" {
		t.Fatalf("deadline = %+v", s)
	}
	if s := StatusFromError(context.Canceled, nil); s.Name != "CANCELLED" {
		t.Fatalf("canceled = %+v", s)
	}
	if s := StatusFromError(errors.New("x"), nil); s.Name != "UNKNOWN" {
		t.Fatalf("unknown = %+v", s)
	}
	bin, _ := proto.Marshal(st.Proto())
	if s := StatusFromParts(5, "m", bin, nil); len(s.Details) != 1 || s.Name != "NOT_FOUND" {
		t.Fatalf("parts = %+v", s)
	}
	if s := StatusFromParts(99, "m", []byte("garbage"), nil); s.Name != "CODE(99)" || len(s.Details) != 0 {
		t.Fatalf("parts garbage = %+v", s)
	}
	// Unknown detail type: raw bytes are kept.
	sp := st.Proto()
	sp.Details[0].TypeUrl = "type.googleapis.com/x.Unknown"
	if s := StatusFromProto(sp, nil); s.Details[0].(map[string]any)["value_base64"] == nil {
		t.Fatalf("unknown detail = %+v", s.Details[0])
	}
	ei, _ := proto.Marshal(&errdetails.ErrorInfo{Reason: "C"})
	if v, ok := DecodeTyped("google.rpc.ErrorInfo", ei, nil); !ok || v.(map[string]any)["reason"] != "C" {
		t.Fatalf("typed = %v %v", v, ok)
	}
	if _, ok := DecodeTyped("x.Nope", ei, nil); ok {
		t.Fatal("unknown typed decoded")
	}
}

// testFile builds a small dynamic file: message T { bytes b = 1; repeated
// N ns = 2; map<string, bytes> m = 3; google.protobuf.BytesValue w = 4;
// google.protobuf.Timestamp ts = 5; string s = 6; } message N { bytes b = 1; }
func testFile(t *testing.T) (*protoregistry.Files, protoreflect.MessageDescriptor) {
	t.Helper()
	s := func(v string) *string { return &v }
	i := func(v int32) *int32 { return &v }
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	typ := func(k descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type { return &k }
	fdp := &descriptorpb.FileDescriptorProto{
		Name: s("t.proto"), Package: s("t"), Syntax: s("proto3"),
		Dependency: []string{"google/protobuf/wrappers.proto", "google/protobuf/timestamp.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: s("T"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: s("b"), Number: i(1), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_BYTES), JsonName: s("b")},
				{Name: s("ns"), Number: i(2), Label: rep, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE), TypeName: s(".t.N"), JsonName: s("ns")},
				{Name: s("m"), Number: i(3), Label: rep, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE), TypeName: s(".t.T.MEntry"), JsonName: s("m")},
				{Name: s("w"), Number: i(4), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE), TypeName: s(".google.protobuf.BytesValue"), JsonName: s("w")},
				{Name: s("ts"), Number: i(5), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE), TypeName: s(".google.protobuf.Timestamp"), JsonName: s("ts")},
				{Name: s("s"), Number: i(6), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_STRING), JsonName: s("s")},
			}, NestedType: []*descriptorpb.DescriptorProto{{
				Name: s("MEntry"), Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: s("key"), Number: i(1), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_STRING), JsonName: s("key")},
					{Name: s("value"), Number: i(2), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_BYTES), JsonName: s("value")},
				},
			}}},
			{Name: s("N"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: s("b"), Number: i(1), Label: opt, Type: typ(descriptorpb.FieldDescriptorProto_TYPE_BYTES), JsonName: s("b")},
			}},
		},
	}
	reg := new(protoregistry.Files)
	// The well-known dependencies are missing from the set: they come
	// from the global registry.
	if err := RegisterProtos(reg, []*descriptorpb.FileDescriptorProto{fdp}); err != nil {
		t.Fatal(err)
	}
	d, err := reg.FindDescriptorByName("t.T")
	if err != nil {
		t.Fatal(err)
	}
	return reg, d.(protoreflect.MessageDescriptor)
}

func TestCodecBytesAndFiles(t *testing.T) {
	reg, md := testFile(t)
	files := map[string][]byte{"a.bin": {1, 2, 3}, "b.bin": []byte("bee")}
	c := NewCodec(reg, func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return b, nil
		}
		return nil, errors.New("not allowed")
	})
	m, err := c.NewMessage(md, map[string]any{
		"b":  map[string]any{"$file": "a.bin"},
		"ns": []any{map[string]any{"b": map[string]any{"$file": "b.bin"}}, map[string]any{"b": "AAE="}},
		"m":  map[string]any{"k": map[string]any{"$file": "b.bin"}},
		"w":  map[string]any{"$file": "a.bin"},
		"ts": "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	js, err := c.ToJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(js, &got)
	if got["b"] != "AQID" || got["w"] != "AQID" || got["ts"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("json = %s", js)
	}
	if ns := got["ns"].([]any); ns[0].(map[string]any)["b"] != "YmVl" || ns[1].(map[string]any)["b"] != "AAE=" {
		t.Fatalf("ns = %v", ns)
	}
	if got["m"].(map[string]any)["k"] != "YmVl" {
		t.Fatalf("m = %v", got["m"])
	}
	// Binary round trip and NormalizeJSON.
	bin, _ := proto.Marshal(m)
	if js2, err := c.Unmarshal(md, bin); err != nil || string(js2) != string(js) {
		t.Fatalf("unmarshal = %s %v", js2, err)
	}
	if js3, err := c.NormalizeJSON(md, []byte(`{"s":"x","unknownField":1}`)); err != nil || string(js3) != `{"s":"x"}` {
		t.Fatalf("normalize = %s %v", js3, err)
	}
	c.EmitDefaults, c.UseProtoNames = true, true
	if js4, _ := c.ToJSON(dynamicMsg(c, t, md, nil)); !strings.Contains(string(js4), `"s":""`) {
		t.Fatalf("emit defaults = %s", js4)
	}

	for _, bad := range []any{
		map[string]any{"b": map[string]any{"$file": "secret"}},
		map[string]any{"b": map[string]any{"$file": "a.bin", "extra": 1}},
		map[string]any{"b": map[string]any{"other": 1}},
		map[string]any{"nope": 1},
		"{not json",
	} {
		if _, err := c.NewMessage(md, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	// A JSON string and an empty string are accepted.
	if m, err := c.NewMessage(md, `{"s":"str"}`); err != nil || m.Get(md.Fields().ByName("s")).String() != "str" {
		t.Fatalf("string request: %v", err)
	}
	if _, err := c.NewMessage(md, " "); err != nil {
		t.Fatal(err)
	}
	// Without a loader $file is refused.
	if _, err := NewCodec(reg, nil).NewMessage(md, map[string]any{"b": map[string]any{"$file": "a.bin"}}); err == nil {
		t.Fatal("$file without loader accepted")
	}
}

func dynamicMsg(c *Codec, t *testing.T, md protoreflect.MessageDescriptor, v any) proto.Message {
	t.Helper()
	m, err := c.NewMessage(md, v)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRegisterProtos(t *testing.T) {
	s := func(v string) *string { return &v }
	a := &descriptorpb.FileDescriptorProto{Name: s("a.proto"), Package: s("a"), Syntax: s("proto3"), Dependency: []string{"b.proto"}}
	b := &descriptorpb.FileDescriptorProto{Name: s("b.proto"), Package: s("b"), Syntax: s("proto3")}
	reg := new(protoregistry.Files)
	// Order does not matter; duplicates are skipped.
	if err := RegisterProtos(reg, []*descriptorpb.FileDescriptorProto{a, b, b}); err != nil {
		t.Fatal(err)
	}
	if reg.NumFiles() != 2 {
		t.Fatalf("files = %d", reg.NumFiles())
	}
	missing := &descriptorpb.FileDescriptorProto{Name: s("c.proto"), Dependency: []string{"nope.proto"}}
	if err := RegisterProtos(new(protoregistry.Files), []*descriptorpb.FileDescriptorProto{missing}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing dep: %v", err)
	}
	cyc1 := &descriptorpb.FileDescriptorProto{Name: s("x.proto"), Dependency: []string{"y.proto"}}
	cyc2 := &descriptorpb.FileDescriptorProto{Name: s("y.proto"), Dependency: []string{"x.proto"}}
	if err := RegisterProtos(new(protoregistry.Files), []*descriptorpb.FileDescriptorProto{cyc1, cyc2}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
}

func TestDescribeAndTemplate(t *testing.T) {
	_, md := testFile(t)
	mi := DescribeMessage(md)
	if mi.Name != "t.T" || len(mi.Fields) != 6 {
		t.Fatalf("message = %+v", mi)
	}
	byName := map[string]FieldInfo{}
	for _, f := range mi.Fields {
		byName[f.Name] = f
	}
	if byName["m"].Label != "map" || byName["m"].MapValue != "bytes" || byName["ns"].Label != "repeated" || byName["ts"].Type != "google.protobuf.Timestamp" {
		t.Fatalf("fields = %+v", byName)
	}
	tmpl, ok := Template(md).(map[string]any)
	if !ok || len(tmpl) == 0 {
		t.Fatalf("template = %v", Template(md))
	}
	// bytes fields carry a hint; the rest of the template is a valid request.
	if s, _ := tmpl["b"].(string); !strings.Contains(s, "$file") {
		t.Fatalf("bytes hint = %v", tmpl["b"])
	}
	delete(tmpl, "b")
	delete(tmpl, "ns")
	c := NewCodec(nil, nil)
	b, _ := json.Marshal(tmpl)
	var v any
	json.Unmarshal(b, &v)
	if _, err := c.NewMessage(md, v); err != nil {
		t.Fatalf("template %s is not a valid request: %v", b, err)
	}
	if !strings.Contains(ProtoText(md), "message t.T {") {
		t.Fatalf("text = %s", ProtoText(md))
	}
	if KindOf(md) != "message" || KindOf(md.Fields().Get(0)) != "field" {
		t.Fatal("kinds")
	}
}
