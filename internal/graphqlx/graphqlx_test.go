package graphqlx

import (
	"encoding/json"
	"flag"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
		t.Fatalf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func loadSchema(t *testing.T) *Schema {
	t.Helper()
	raw, err := os.ReadFile("testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := DecodeSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPrintSDLGolden(t *testing.T) {
	s := loadSchema(t)
	out, err := PrintSDL(s, PrintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "schema.graphql", out)
	out, err = PrintSDL(s, PrintOptions{Descriptions: true})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "schema_descriptions.graphql", out)
}

func TestPrintSDLSingleType(t *testing.T) {
	s := loadSchema(t)
	out, err := PrintSDL(s, PrintOptions{TypeName: "UserFilter"})
	if err != nil {
		t.Fatal(err)
	}
	want := "input UserFilter {\n  active: Boolean = true\n  nameContains: String\n  roles: [Role!] = [ADMIN, USER]\n}\n"
	if out != want {
		t.Fatalf("got\n%s", out)
	}
	if _, err := PrintSDL(s, PrintOptions{TypeName: "Usr"}); err == nil || !strings.Contains(err.Error(), "User") {
		t.Fatalf("expected suggestion error, got %v", err)
	}
	out, err = PrintSDL(s, PrintOptions{TypeName: "@cacheControl"})
	if err != nil || out != "directive @cacheControl(maxAge: Int = 0) on FIELD_DEFINITION | OBJECT\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestSchemaBlockForCustomRoots(t *testing.T) {
	s := &Schema{QueryType: &namedType{Name: "Root"}}
	out, _ := PrintSDL(s, PrintOptions{})
	if out != "schema {\n  query: Root\n}\n" {
		t.Fatalf("%q", out)
	}
}

func TestSetNullAtPath(t *testing.T) {
	ops := map[string]any{"variables": map[string]any{"input": map[string]any{"name": "x"}}}
	for _, p := range []string{"variables.file", "variables.files.1", "variables.input.avatar", "variables.nested.0.docs.0"} {
		if err := SetNullAtPath(ops, p); err != nil {
			t.Fatal(p, err)
		}
	}
	b, _ := json.Marshal(ops)
	want := `{"variables":{"file":null,"files":[null,null],"input":{"avatar":null,"name":"x"},"nested":[{"docs":[null]}]}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if err := SetNullAtPath(ops, "file"); err == nil {
		t.Fatal("expected error for single-segment path")
	}
}

func TestMultipartStream(t *testing.T) {
	op := Request{Query: "mutation($file: Upload!, $files: [Upload!]!) { a }", Variables: map[string]any{"files": []any{nil, nil}}}
	files := []UploadFile{
		{Paths: []string{"variables.file"}, Name: "a.txt", ContentType: "text/plain", Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("alpha")), nil }},
		{Paths: []string{"variables.files.0", "variables.files.1"}, Name: `we"ird.bin`, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("beta")), nil }},
	}
	body, ct, err := Multipart(op, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(ct)
	mr := multipart.NewReader(body, params["boundary"])
	var names []string
	parts := map[string]string{}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		names = append(names, p.FormName())
		parts[p.FormName()] = string(b)
		if p.FormName() == "1" && p.FileName() != `we"ird.bin` {
			t.Fatalf("filename %q", p.FileName())
		}
	}
	if !reflect.DeepEqual(names, []string{"operations", "map", "0", "1"}) {
		t.Fatal(names)
	}
	if parts["map"] != `{"0":["variables.file"],"1":["variables.files.0","variables.files.1"]}` {
		t.Fatal(parts["map"])
	}
	var o map[string]any
	json.Unmarshal([]byte(parts["operations"]), &o)
	if v := o["variables"].(map[string]any); v["file"] != nil || len(v["files"].([]any)) != 2 {
		t.Fatal(parts["operations"])
	}
	if parts["0"] != "alpha" || parts["1"] != "beta" {
		t.Fatal(parts)
	}
}

func TestParseResponse(t *testing.T) {
	r, ok := ParseResponse([]byte(`{"data":{"a":1},"errors":[{"message":"x"}],"extensions":{"cost":3}}`))
	if !ok || string(r.Data) != `{"a":1}` || string(r.Errors) != `[{"message":"x"}]` || string(r.Extensions) != `{"cost":3}` {
		t.Fatal(r, ok)
	}
	if _, ok := ParseResponse([]byte(`<html>`)); ok {
		t.Fatal("html is not a graphql response")
	}
}

func TestGetURL(t *testing.T) {
	r := Request{Query: "{a}", Variables: map[string]any{"x": 1}, OperationName: "Q"}
	r.PersistedQuery("abc")
	u, err := r.GetURL("http://h/graphql?k=v")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "query=%7Ba%7D") || !strings.Contains(u, "variables=%7B%22x%22%3A1%7D") || !strings.Contains(u, "operationName=Q") || !strings.Contains(u, "sha256Hash") || !strings.Contains(u, "k=v") {
		t.Fatal(u)
	}
}
