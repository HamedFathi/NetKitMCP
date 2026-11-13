package curlparse

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTokenizePOSIX(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`curl https://x`, []string{"curl", "https://x"}},
		{`curl 'a b' "c d" e\ f`, []string{"curl", "a b", "c d", "e f"}},
		{`curl "a \"q\" \$HOME \\ \x"`, []string{"curl", `a "q" $HOME \ \x`}},
		{`curl 'it'\''s'`, []string{"curl", "it's"}},
		{"curl $'line1\\nline2\\t\\x41\\u00e9\\'q\\101'", []string{"curl", "line1\nline2\tAé'qA"}},
		{"curl \\\n  -H 'A: b' \\\n  https://x", []string{"curl", "-H", "A: b", "https://x"}},
		{"curl \\\r\n  https://x", []string{"curl", "https://x"}},
		{"curl -d \"multi\\\nline\" x", []string{"curl", "-d", "multiline", "x"}},
		{"curl x # comment here\n", []string{"curl", "x"}},
		{"curl a#b", []string{"curl", "a#b"}},
		{"curl.exe `\n -H \"A: b\" `\n https://x", []string{"curl.exe", "-H", "A: b", "https://x"}},
		{`curl ''`, []string{"curl", ""}},
	}
	for _, c := range cases {
		got, err := Tokenize(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{`curl 'x`, `curl "x`, `curl $'x`} {
		if _, err := Tokenize(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestTokenizeCmd(t *testing.T) {
	// Chrome "Copy as cURL (cmd)" style.
	in := "curl ^\"https://example.com/api?a=1^&b=2^\" ^\n" +
		"  -H ^\"accept: application/json^\" ^\n" +
		"  --data-raw ^\"^{^\\^\"name^\\^\":^\\^\"x y^\\^\"^}^\" ^\n" +
		"  --compressed"
	got, err := Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"curl", "https://example.com/api?a=1&b=2", "-H", "accept: application/json", "--data-raw", `{"name":"x y"}`, "--compressed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// Plain cmd quoting with ^ continuation and \" escapes.
	got, err = Tokenize("curl -X POST ^\r\n -d \"{\\\"a\\\":1}\" https://x")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"curl", "-X", "POST", "-d", `{"a":1}`, "https://x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func mustParse(t *testing.T, cmd string) *Result {
	t.Helper()
	r, err := Parse(cmd)
	if err != nil {
		t.Fatalf("Parse(%q): %v", cmd, err)
	}
	return r
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestParseBasicGET(t *testing.T) {
	r := mustParse(t, `curl https://api.example.com/users`)
	if r.Tool != ToolRequest || r.Arguments["method"] != "GET" || r.Arguments["url"] != "https://api.example.com/users" {
		t.Fatalf("%+v", r)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("warnings: %v", r.Warnings)
	}
	r = mustParse(t, `$ curl example.com/x`)
	if r.Arguments["url"] != "http://example.com/x" {
		t.Fatalf("scheme default: %v", r.Arguments["url"])
	}
}

func TestParseHeadersAndOptions(t *testing.T) {
	r := mustParse(t, `curl -sSL -X PATCH 'https://h/p' -H 'Content-Type: application/json' -H "X-A: 1" -H "x-a: 2" `+
		`-A agent/1 -e https://ref -b 'a=1' -b 'b=2' -k --compressed --max-time 12.5 -x proxy:3128 -U pu:pp `+
		`--http2 --max-redirs 3 --cacert ca.pem --cert c.pem --key k.pem -u user:pa:ss --data-raw '{"x":1}'`)
	a := r.Arguments
	if r.Tool != ToolRequest || a["method"] != "PATCH" || a["body"] != `{"x":1}` {
		t.Fatalf("%s", asJSON(r))
	}
	h := a["headers"].(map[string]string)
	want := map[string]string{
		"Content-Type": "application/json", "x-a": "1, 2", "User-Agent": "agent/1",
		"Referer": "https://ref", "Cookie": "a=1; b=2", "Accept-Encoding": "gzip, deflate",
	}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("headers: %v", h)
	}
	checks := map[string]any{
		"insecure_skip_verify": true, "follow_redirects": true, "timeout_seconds": 12.5,
		"proxy": "http://pu:pp@proxy:3128", "http_version": "2", "max_redirects": 3,
		"ca_cert": "ca.pem", "client_cert": "c.pem", "client_key": "k.pem",
	}
	for k, v := range checks {
		if !reflect.DeepEqual(a[k], v) {
			t.Errorf("%s = %#v, want %#v", k, a[k], v)
		}
	}
	auth := a["auth"].(map[string]any)
	if auth["type"] != "basic" || auth["username"] != "user" || auth["password"] != "pa:ss" {
		t.Fatalf("auth: %v", auth)
	}
}

func TestParseShortClusterWithValue(t *testing.T) {
	r := mustParse(t, `curl -XPUT -HAccept:text/plain -dfoo https://h`)
	a := r.Arguments
	if a["method"] != "PUT" || a["body"] != "foo" || a["headers"].(map[string]string)["Accept"] != "text/plain" {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseFormData(t *testing.T) {
	r := mustParse(t, `curl https://h/login -d 'user=bob' -d 'pass=a%20b&x=1+2'`)
	if r.Tool != ToolForm {
		t.Fatalf("tool %s: %s", r.Tool, asJSON(r))
	}
	got := asJSON(r.Arguments["fields"])
	want := `[{"name":"user","value":"bob"},{"name":"pass","value":"a b"},{"name":"x","value":"1 2"}]`
	if got != want {
		t.Fatalf("fields %s", got)
	}
	if _, ok := r.Arguments["method"]; ok {
		t.Fatalf("POST should be implicit for the form tool")
	}
	// Non-form data stays a raw body with curl's default content type.
	r = mustParse(t, `curl https://h -d '{"a":1}'`)
	if r.Tool != ToolRequest || r.Arguments["body"] != `{"a":1}` || r.Arguments["method"] != "POST" ||
		r.Arguments["headers"].(map[string]string)["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseDataURLEncode(t *testing.T) {
	// Pieces without "=" make it a raw body rather than form fields.
	r := mustParse(t, `curl https://h --data-urlencode 'q=a b&c' --data-urlencode '=x/y' --data-urlencode plain`)
	if r.Tool != ToolRequest || r.Arguments["body"] != "q=a%20b%26c&x%2Fy&plain" {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl https://h --data-urlencode 'q=a b&c' --data-urlencode 'z=é'`)
	got := asJSON(r.Arguments["fields"])
	if got != `[{"name":"q","value":"a b\u0026c"},{"name":"z","value":"é"}]` {
		t.Fatalf("fields %s", got)
	}
	r = mustParse(t, `curl https://h --data-urlencode '=x/y'`)
	if r.Tool != ToolRequest || r.Arguments["body"] != "x%2Fy" {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl https://h --data-urlencode @body.txt`)
	if r.Arguments["body_file"] != "body.txt" || len(r.Warnings) == 0 {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseDataFile(t *testing.T) {
	r := mustParse(t, `curl -X PUT https://h/obj --data-binary @/tmp/in.bin -H 'Content-Type: application/octet-stream'`)
	a := r.Arguments
	if r.Tool != ToolRequest || a["body_file"] != "/tmp/in.bin" || a["method"] != "PUT" {
		t.Fatalf("%s", asJSON(r))
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", r.Warnings)
	}
	r = mustParse(t, `curl https://h -d @data.txt`)
	if r.Arguments["body_file"] != "data.txt" || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "strips newlines") {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseJSONFlag(t *testing.T) {
	r := mustParse(t, `curl --json '{"a":1}' https://h/api`)
	h := r.Arguments["headers"].(map[string]string)
	if r.Tool != ToolRequest || r.Arguments["body"] != `{"a":1}` || h["Content-Type"] != "application/json" || h["Accept"] != "application/json" || r.Arguments["method"] != "POST" {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseGet(t *testing.T) {
	r := mustParse(t, `curl -G https://h/search?x=1 -d q=hello --data-urlencode 'n=a b'`)
	if r.Tool != ToolRequest || r.Arguments["method"] != "GET" || r.Arguments["url"] != "https://h/search?x=1&q=hello&n=a%20b" {
		t.Fatalf("%s", asJSON(r))
	}
	if _, ok := r.Arguments["body"]; ok {
		t.Fatal("body should move to the query")
	}
}

func TestParseHead(t *testing.T) {
	r := mustParse(t, `curl -I https://h`)
	if r.Arguments["method"] != "HEAD" {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseMultipart(t *testing.T) {
	r := mustParse(t, `curl -F 'title=Hello; world' -F 'file=@/data/a.png;type=image/png' `+
		`-F 'file=@b.txt;filename=renamed.txt' -F 'meta=<meta.json' --form-string 'raw=@notafile' `+
		`-F 'q="x;y";type=text/plain' -H 'Content-Type: multipart/form-data; boundary=abc' -X PUT https://h/up`)
	if r.Tool != ToolMultipart {
		t.Fatalf("%s", asJSON(r))
	}
	got := asJSON(r.Arguments["parts"])
	want := `[{"name":"title","value":"Hello; world"},` +
		`{"content_type":"image/png","file":"/data/a.png","name":"file"},` +
		`{"file":"b.txt","filename":"renamed.txt","name":"file"},` +
		`{"file":"meta.json","name":"meta"},` +
		`{"name":"raw","value":"@notafile"},` +
		`{"content_type":"text/plain","name":"q","value":"x;y"}]`
	if got != want {
		t.Fatalf("parts\n got %s\nwant %s", got, want)
	}
	if r.Arguments["method"] != "PUT" {
		t.Fatalf("method %v", r.Arguments["method"])
	}
	if _, ok := r.Arguments["headers"]; ok {
		t.Fatalf("Content-Type with a stale boundary must be dropped: %v", r.Arguments["headers"])
	}
}

func TestParseUpload(t *testing.T) {
	r := mustParse(t, `curl -T ./video.mp4 -H 'Content-Type: video/mp4' -H 'x-ms-blob-type: BlockBlob' --retry 3 'https://acct.blob.core.windows.net/c/v.mp4?sv=1&sig=abc'`)
	a := r.Arguments
	if r.Tool != ToolUpload || a["file"] != "./video.mp4" || a["content_type"] != "video/mp4" || a["retries"] != 3 {
		t.Fatalf("%s", asJSON(r))
	}
	if _, ok := a["method"]; ok {
		t.Fatal("PUT is the default for http_upload")
	}
	if a["headers"].(map[string]string)["x-ms-blob-type"] != "BlockBlob" {
		t.Fatalf("%v", a["headers"])
	}
}

func TestParseOutput(t *testing.T) {
	r := mustParse(t, `curl -o out/file.zip https://h/dl`)
	if r.Arguments["save_to"] != "out/file.zip" {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl -LO https://h/path/archive.tar.gz`)
	if r.Arguments["save_to"] != "archive.tar.gz" || r.Arguments["follow_redirects"] != true {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestParseAuthVariants(t *testing.T) {
	r := mustParse(t, `curl --oauth2-bearer tok https://h`)
	if asJSON(r.Arguments["auth"]) != `{"token":"tok","type":"bearer"}` {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl --digest -u a:b https://h`)
	if r.Arguments["auth"].(map[string]any)["type"] != "digest" {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl --aws-sigv4 'aws:amz:eu-west-1:s3' -u AK:SK https://b.s3.amazonaws.com/k`)
	if asJSON(r.Arguments["auth"]) != `{"aws":{"access_key_id":"AK","region":"eu-west-1","secret_access_key":"SK","service":"s3"},"type":"aws_sigv4"}` {
		t.Fatalf("%s", asJSON(r))
	}
	r = mustParse(t, `curl -u onlyuser https://h`)
	if len(r.Warnings) == 0 {
		t.Fatal("expected a no-password warning")
	}
}

func TestParseHTTPVersionsAndProxies(t *testing.T) {
	for flag, want := range map[string]string{"--http1.1": "1.1", "--http2-prior-knowledge": "2", "--http3": "3", "--http3-only": "3"} {
		r := mustParse(t, "curl "+flag+" https://h")
		if r.Arguments["http_version"] != want {
			t.Errorf("%s: %v", flag, r.Arguments["http_version"])
		}
	}
	r := mustParse(t, `curl --socks5-hostname 127.0.0.1:9050 https://h`)
	if r.Arguments["proxy"] != "socks5h://127.0.0.1:9050" {
		t.Fatalf("%v", r.Arguments["proxy"])
	}
}

func TestParseWarnings(t *testing.T) {
	r := mustParse(t, `curl --resolve h:443:1.2.3.4 --frobnicate -Wq https://h --next https://other`)
	joined := strings.Join(r.Warnings, "\n")
	for _, w := range []string{"--resolve", "--frobnicate", "-W", "--next", "several URLs"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing warning about %s in:\n%s", w, joined)
		}
	}
	if r.Arguments["url"] != "https://h" {
		t.Fatalf("url %v", r.Arguments["url"])
	}
}

func TestParseRemoveHeaderAndEmptyHeader(t *testing.T) {
	r := mustParse(t, `curl -H 'X-A: 1' -H 'X-A:' -H 'X-Empty;' https://h`)
	h := r.Arguments["headers"].(map[string]string)
	if _, ok := h["X-A"]; ok || h["X-Empty"] != "" || len(h) != 1 {
		t.Fatalf("%v", h)
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []string{``, `curl`, `curl -H`, `curl -s -v`, `curl -F novalue https://h`} {
		if _, err := Parse(c); err == nil {
			t.Errorf("%q: expected error", c)
		}
	}
}

func TestParseWindowsChromeCopy(t *testing.T) {
	in := "curl ^\"https://api.example.com/v1/items^\" ^\n" +
		"  -H ^\"authorization: Bearer abc^\" ^\n" +
		"  -H ^\"content-type: application/json^\" ^\n" +
		"  --data-raw ^\"^{^\\^\"q^\\^\":^\\^\"50^%^\\^\"^}^\""
	r := mustParse(t, in)
	if r.Arguments["body"] != `{"q":"50%"}` || r.Arguments["method"] != "POST" {
		t.Fatalf("%s", asJSON(r))
	}
	if r.Arguments["headers"].(map[string]string)["authorization"] != "Bearer abc" {
		t.Fatalf("%s", asJSON(r))
	}
}

func TestTokenizeTrailingBlanksAfterContinuation(t *testing.T) {
	cases := map[string][]string{
		"curl -X POST \\  \n  -H 'A: b' \\\t\n  https://x":    {"curl", "-X", "POST", "-H", "A: b", "https://x"},
		"curl -X POST ^ \r\n  -H \"A: b\" ^  \r\n  https://x": {"curl", "-X", "POST", "-H", "A: b", "https://x"},
		"curl.exe -X POST `  \n  https://x":                   {"curl.exe", "-X", "POST", "https://x"},
	}
	for in, want := range cases {
		got, err := Tokenize(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n got %q (%v)\nwant %q", in, got, err, want)
		}
	}
}
