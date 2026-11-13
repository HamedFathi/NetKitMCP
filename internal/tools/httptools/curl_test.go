package httptools_test

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

type curlResult struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Warnings  []string       `json:"warnings"`
}

func curl(t *testing.T, h *tooltest.Harness, cmd string) curlResult {
	t.Helper()
	var r curlResult
	h.MustOK("curl_to_request", map[string]any{"command": cmd}).Decode(t, &r)
	return r
}

func warned(r curlResult, substr string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func headersOf(t *testing.T, r curlResult) map[string]any {
	t.Helper()
	hs, _ := r.Arguments["headers"].(map[string]any)
	return hs
}

func TestCurlBashMultiline(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	cmd := "curl -X POST '" + srv.URL + "/v1/items?limit=10&q=a%20b' \\\n" +
		"  -H 'Content-Type: application/json' \\\n" +
		"  -H \"Authorization: Bearer abc.def\" \\\n" +
		"  -H 'X-Quoted: \"double\" inside' \\\n" +
		"  -H \"X-Apostrophe: it's\" \\\n" +
		"  --data-raw '{\"name\":\"widget\",\"tags\":[\"a b\"]}' \\\n" +
		"  --compressed -k -sS"
	r := curl(t, h, cmd)
	a := r.Arguments
	if r.Tool != "http_request" || a["method"] != "POST" || a["url"] != srv.URL+"/v1/items?limit=10&q=a%20b" {
		t.Fatalf("%+v", r)
	}
	if a["body"] != `{"name":"widget","tags":["a b"]}` || a["insecure_skip_verify"] != true {
		t.Fatalf("args %v", a)
	}
	want := map[string]any{
		"Content-Type": "application/json", "Authorization": "Bearer abc.def", "X-Quoted": `"double" inside`,
		"X-Apostrophe": "it's", "Accept-Encoding": "gzip, deflate",
	}
	if hs := headersOf(t, r); !reflect.DeepEqual(hs, want) {
		t.Fatalf("headers %v", hs)
	}
	if !warned(r, "--compressed") {
		t.Fatalf("warnings %v", r.Warnings)
	}

	// The converted arguments run as-is.
	e := decodeEcho(t, call(t, h, r.Tool, a))
	if e.Method != "POST" || e.Path != "/v1/items" || e.RawQuery != "limit=10&q=a%20b" || e.Body != `{"name":"widget","tags":["a b"]}` {
		t.Fatalf("echo %+v", e)
	}
	if e.Headers["Authorization"][0] != "Bearer abc.def" || e.Headers["X-Quoted"][0] != `"double" inside` || e.Headers["Content-Type"][0] != "application/json" {
		t.Fatalf("echo headers %v", e.Headers)
	}
}

func TestCurlWindowsCmd(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	cmd := "curl -X PUT \"" + srv.URL + "/v1/items/42\" ^\r\n" +
		"  -H \"Content-Type: application/json\" ^\r\n" +
		"  -u \"admin:p@ss word\" ^\r\n" +
		"  -d \"{\\\"name\\\":\\\"x y\\\"}\""
	r := curl(t, h, cmd)
	a := r.Arguments
	if r.Tool != "http_request" || a["method"] != "PUT" || a["body"] != `{"name":"x y"}` || a["url"] != srv.URL+"/v1/items/42" {
		t.Fatalf("%+v", r)
	}
	auth, _ := a["auth"].(map[string]any)
	if auth["type"] != "basic" || auth["username"] != "admin" || auth["password"] != "p@ss word" {
		t.Fatalf("auth %v", auth)
	}
	e := decodeEcho(t, call(t, h, r.Tool, a))
	if e.Method != "PUT" || e.Body != `{"name":"x y"}` || e.Headers["Authorization"][0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:p@ss word")) {
		t.Fatalf("echo %+v", e)
	}

	// Chrome "Copy as cURL (cmd)" with ^" escapes.
	chrome := "curl ^\"" + srv.URL + "/api?a=1^&b=2^\" ^\n" +
		"  -H ^\"accept: application/json^\" ^\n" +
		"  -H ^\"cookie: sid=abc^\" ^\n" +
		"  --data-raw ^\"^{^\\^\"q^\\^\":^\\^\"x^\\^\"^}^\" ^\n" +
		"  --compressed"
	r = curl(t, h, chrome)
	if r.Arguments["url"] != srv.URL+"/api?a=1&b=2" || r.Arguments["body"] != `{"q":"x"}` || headersOf(t, r)["cookie"] != "sid=abc" {
		t.Fatalf("chrome cmd: %+v", r)
	}

	// PowerShell backtick continuations.
	r = curl(t, h, "curl.exe -X DELETE `\n  \""+srv.URL+"/x\" `\n  -H \"X-A: 1\"")
	if r.Arguments["method"] != "DELETE" || headersOf(t, r)["X-A"] != "1" {
		t.Fatalf("powershell: %+v", r)
	}
}

func TestCurlDataFilesAndForms(t *testing.T) {
	h := tooltest.New(t, "http")
	srv, last := multipartServer(t)
	p, sum := writeBig(t, h, "payload.bin", 70000)
	h.WriteInput("a.txt", []byte("alpha"))

	// --data-binary @file streams the file.
	r := curl(t, h, `curl --data-binary @payload.bin -H 'Content-Type: application/octet-stream' https://h.example/up`)
	if r.Tool != "http_request" || r.Arguments["body_file"] != "payload.bin" || r.Arguments["method"] != "POST" || len(r.Warnings) != 0 {
		t.Fatalf("%+v", r)
	}
	// -d @file: newline stripping is flagged; missing files are flagged.
	r = curl(t, h, `curl -d @missing.json https://h.example/up`)
	if r.Arguments["body_file"] != "missing.json" || !warned(r, "strips newlines") || !warned(r, `body_file "missing.json"`) {
		t.Fatalf("%+v", r)
	}
	// -d form data becomes http_form_request.
	r = curl(t, h, `curl https://h.example/login -d 'user=bob' --data "pass=a%20b"`)
	if r.Tool != "http_form_request" || !reflect.DeepEqual(r.Arguments["fields"], []any{
		map[string]any{"name": "user", "value": "bob"}, map[string]any{"name": "pass", "value": "a b"},
	}) {
		t.Fatalf("%+v", r)
	}

	// -F becomes a multipart request that runs end to end.
	r = curl(t, h, "curl "+srv.URL+"/upload \\\n"+
		"  -F 'title=Hello world' \\\n"+
		"  -F \"files=@a.txt;type=text/x-alpha\" \\\n"+
		"  -F 'files=@payload.bin;filename=renamed.bin' \\\n"+
		"  -F 'meta={\"a\":1};type=application/json' \\\n"+
		"  -H 'Authorization: Bearer t0k'")
	if r.Tool != "http_multipart_request" {
		t.Fatalf("%+v", r)
	}
	parts, _ := r.Arguments["parts"].([]any)
	if len(parts) != 4 {
		t.Fatalf("parts %v", parts)
	}
	res := call(t, h, r.Tool, r.Arguments)
	g := last()
	if res.Status != 200 || len(g.Parts) != 4 || g.Err != "" {
		t.Fatalf("server %+v", g)
	}
	if g.Parts[0].Text != "Hello world" || g.Parts[1].Filename != "a.txt" || g.Parts[1].ContentType != "text/x-alpha" || g.Parts[1].Text != "alpha" {
		t.Fatalf("parts %+v", g.Parts[:2])
	}
	if g.Parts[2].Filename != "renamed.bin" || g.Parts[2].SHA256 != sum || g.Parts[3].ContentType != "application/json" || g.Parts[3].Text != `{"a":1}` {
		t.Fatalf("parts %+v", g.Parts[2:])
	}
	_ = p

	// -T is an upload.
	r = curl(t, h, `curl -T payload.bin -H 'Content-Type: application/zip' --retry 3 'https://bucket.example/k?X-Amz-Signature=abc&X-Amz-Credential=x'`)
	if r.Tool != "http_upload" || r.Arguments["file"] != "payload.bin" || r.Arguments["content_type"] != "application/zip" || r.Arguments["retries"] != float64(3) {
		t.Fatalf("%+v", r)
	}
	if !warned(r, "signed parameters") {
		t.Fatalf("signed URL not flagged: %v", r.Warnings)
	}

	// -o into an existing file is flagged (no overwrite by default).
	h.MustOK("http_request", map[string]any{"url": srv.URL, "save_to": "out.json"})
	r = curl(t, h, "curl -o out.json "+srv.URL)
	if r.Arguments["save_to"] != "out.json" || !warned(r, "overwrite=true") {
		t.Fatalf("%+v", r)
	}
}

func TestCurlUnsupportedAndErrors(t *testing.T) {
	h := tooltest.New(t, "http")
	r := curl(t, h, `curl --foo-bar --unix-socket /var/run/docker.sock -K my.cfg -Q x http://localhost/containers/json`)
	for _, w := range []string{"--foo-bar", "--unix-socket", "config files are not read"} {
		if !warned(r, w) {
			t.Errorf("no warning for %s: %v", w, r.Warnings)
		}
	}
	if r.Arguments["url"] != "http://localhost/containers/json" {
		t.Fatalf("%+v", r)
	}
	r = curl(t, h, `curl -b cookies.txt --negotiate -u : https://h.example`)
	if !warned(r, "reads cookies from a file") {
		t.Fatalf("%v", r.Warnings)
	}

	h.MustFail("curl_to_request", map[string]any{"command": "  "}, "command is required")
	h.MustFail("curl_to_request", map[string]any{"command": "curl -H 'X: 1'"}, "no URL")
	h.MustFail("curl_to_request", map[string]any{"command": "curl 'https://h.example"}, "unterminated")
	h.MustFail("curl_to_request", map[string]any{"command": "curl https://h.example -X"}, "needs a value")
	h.MustFail("curl_to_request", map[string]any{"command": "curl -F novalue https://h.example"}, "name=content")
}
