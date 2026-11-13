package httptools_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

type echo struct {
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	RawQuery      string              `json:"raw_query"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	ContentLength int64               `json:"content_length"`
	Chunked       bool                `json:"chunked"`
}

func echoServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(echo{
			Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Headers: r.Header,
			Body: string(b), ContentLength: r.ContentLength, Chunked: len(r.TransferEncoding) > 0,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func decodeEcho(t *testing.T, r response) echo {
	t.Helper()
	var e echo
	if err := json.Unmarshal([]byte(r.Body), &e); err != nil {
		t.Fatalf("echo body: %v\n%s", err, r.Body)
	}
	return e
}

func TestHTTPRequestMethodsQueryHeadersJSON(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)

	r := call(t, h, "http_request", map[string]any{
		"method":          "propfind",
		"url":             srv.URL + "/dav?existing=1",
		"query":           map[string]any{"tag": []any{"a", "b c"}, "n": 5, "flag": true},
		"headers":         map[string]string{"X-Test": "yes", "Authorization": "Bearer secret-token", "Depth": "1"},
		"json":            map[string]any{"hello": "world"},
		"include_request": true,
	})
	e := decodeEcho(t, r)
	if r.Status != 200 || e.Method != "PROPFIND" || e.Path != "/dav" {
		t.Fatalf("status %d method %s path %s", r.Status, e.Method, e.Path)
	}
	if e.RawQuery != "existing=1&flag=true&n=5&tag=a&tag=b+c" {
		t.Fatalf("query %q", e.RawQuery)
	}
	if e.Body != `{"hello":"world"}` || e.Headers["Content-Type"][0] != "application/json" || e.Headers["X-Test"][0] != "yes" {
		t.Fatalf("echo %+v", e)
	}
	if !strings.HasPrefix(e.Headers["User-Agent"][0], "netkit-mcp/") {
		t.Fatalf("user agent %v", e.Headers["User-Agent"])
	}
	if r.Request == nil || r.Request.Headers["Authorization"] != "Bearer ***" || r.Request.Method != "PROPFIND" {
		t.Fatalf("request echo %+v", r.Request)
	}
	if r.Request.Body == nil || r.Request.Body.Kind != "json" || r.Request.Body.SizeBytes != 17 {
		t.Fatalf("body summary %+v", r.Request.Body)
	}
	// Total may be 0 on Windows, whose clock is too coarse for a loopback request.
	if r.Protocol != "HTTP/1.1" || r.TimingMS.Total < 0 || r.ContentType != "application/json" {
		t.Fatalf("protocol %s timing %+v", r.Protocol, r.TimingMS)
	}

	// Raw text body defaults to POST; base64 body is decoded.
	r = call(t, h, "http_request", map[string]any{"url": srv.URL, "body": "plain text"})
	if e := decodeEcho(t, r); e.Method != "POST" || e.Body != "plain text" || !strings.HasPrefix(e.Headers["Content-Type"][0], "text/plain") {
		t.Fatalf("echo %+v", e)
	}
	r = call(t, h, "http_request", map[string]any{"url": srv.URL, "method": "PUT", "body_base64": "AAEC/w==", "content_type": "application/x-bin"})
	if e := decodeEcho(t, r); e.Body != "\x00\x01\x02�" || e.ContentLength != 4 || e.Headers["Content-Type"][0] != "application/x-bin" {
		t.Fatalf("echo %+v", e)
	}

	h.MustFail("http_request", map[string]any{"url": srv.URL, "body": "a", "json": 1}, "only one of")
	h.MustFail("http_request", map[string]any{"url": "ftp://x/y"}, "scheme")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "method": "BAD METHOD"}, "invalid HTTP method")
}

func TestHTTPRequestAuth(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if r.Header.Get("Authorization") == "Bearer tok" || (ok && u == "bob" && p == "pw") {
			io.WriteString(w, "welcome")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	r := call(t, h, "http_request", map[string]any{"url": srv.URL, "auth": map[string]any{"type": "bearer", "token": "tok"}})
	if r.Status != 200 || r.Body != "welcome" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	r = call(t, h, "http_request", map[string]any{"url": srv.URL, "auth": map[string]any{"type": "basic", "username": "bob", "password": "pw"}})
	if r.Status != 200 {
		t.Fatalf("basic: %d", r.Status)
	}
	r = call(t, h, "http_request", map[string]any{"url": srv.URL})
	if r.Status != 401 {
		t.Fatalf("no auth: %d (HTTP errors are results, not tool errors)", r.Status)
	}
}

func TestHTTPRequestBodyFileStreamed(t *testing.T) {
	h := tooltest.New(t, "http")
	var gotLen int64
	var gotTE []string
	var gotSum string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen, gotTE = r.ContentLength, r.TransferEncoding
		hs := sha256.New()
		io.Copy(hs, r.Body)
		gotSum = hex.EncodeToString(hs.Sum(nil))
		fmt.Fprint(w, gotSum)
	}))
	defer srv.Close()

	p, sum := writeBig(t, h, "payload.bin", 3<<20+17)
	r := call(t, h, "http_request", map[string]any{"url": srv.URL, "method": "PUT", "body_file": p, "include_request": true})
	if gotSum != sum || gotLen != 3<<20+17 || len(gotTE) != 0 {
		t.Fatalf("server got len=%d te=%v sum match=%v", gotLen, gotTE, gotSum == sum)
	}
	if len(r.UploadedFiles) != 1 || r.UploadedFiles[0].SHA256 != sum || r.UploadedFiles[0].Name != "payload.bin" {
		t.Fatalf("uploaded %+v", r.UploadedFiles)
	}
	if r.Request.Body.SHA256 != sum || r.Request.Body.Kind != "file" {
		t.Fatalf("echo body %+v", r.Request.Body)
	}
	// Relative paths resolve inside the read directory.
	call(t, h, "http_request", map[string]any{"url": srv.URL, "method": "POST", "body_file": "payload.bin"})
	if gotSum != sum {
		t.Fatal("relative body_file")
	}
	// Files outside the allowed directories are refused.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("x"), 0o644)
	h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": outside}, "outside the allowed read directories")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": "../out/../../etc/passwd"}, "")
}

func TestHTTPRequestBodyFileRedirect307(t *testing.T) {
	h := tooltest.New(t, "http")
	var final string
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		final = r.Method + " " + sha(b)
		w.WriteHeader(201)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p, sum := writeBig(t, h, "r.bin", 100000)
	r := call(t, h, "http_request", map[string]any{"url": srv.URL + "/start", "method": "PUT", "body_file": p})
	if r.Status != 201 || final != "PUT "+sum {
		t.Fatalf("status %d final %q", r.Status, final)
	}
	if len(r.Redirects) != 1 || !strings.HasSuffix(r.FinalURL, "/final") {
		t.Fatalf("redirects %v final %s", r.Redirects, r.FinalURL)
	}
}

func TestHTTPRequestRedirects(t *testing.T) {
	h := tooltest.New(t, "http")
	mux := http.NewServeMux()
	mux.HandleFunc("/r/", func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(r.URL.Path, "/r/%d", &n)
		if n <= 0 {
			io.WriteString(w, "done")
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/r/%d", n-1), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := call(t, h, "http_request", map[string]any{"url": srv.URL + "/r/3"})
	if r.Status != 200 || r.Body != "done" || len(r.Redirects) != 3 || !strings.HasSuffix(r.FinalURL, "/r/0") {
		t.Fatalf("%d %q %v %s", r.Status, r.Body, r.Redirects, r.FinalURL)
	}
	r = call(t, h, "http_request", map[string]any{"url": srv.URL + "/r/3", "follow_redirects": false})
	if r.Status != 302 || r.Headers["Location"] != "/r/2" {
		t.Fatalf("no-follow: %d %v", r.Status, r.Headers)
	}
	h.MustFail("http_request", map[string]any{"url": srv.URL + "/r/5", "max_redirects": 2}, "stopped after 2 redirects")
}

// publicHost serves requests for a synthetic public host in-process so the
// redirect-to-private guard can be tested while private targets are blocked.
type publicHost struct {
	base     http.RoundTripper
	location string
}

func (p *publicHost) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() != "public.example" {
		return p.base.RoundTrip(req)
	}
	rec := httptest.NewRecorder()
	http.Redirect(rec, req, p.location, http.StatusFound)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func TestRedirectToPrivateBlocked(t *testing.T) {
	h := tooltest.New(t, "http", tooltest.WithPrivateMode(config.PrivateOptIn))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "internal data")
	}))
	defer srv.Close()

	for _, target := range []string{srv.URL + "/secret", strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/secret", "http://169.254.169.254/latest/meta-data/"} {
		h.Deps.HTTP.TransportHook = func(base http.RoundTripper) http.RoundTripper {
			return &publicHost{base: base, location: target}
		}
		h.MustFail("http_request", map[string]any{"url": "http://public.example/start"}, "allow_private")
	}

	// Direct private targets are blocked too.
	h.MustFail("http_request", map[string]any{"url": srv.URL}, "allow_private")

	// With the opt-in the same redirect is followed.
	h.Deps.HTTP.TransportHook = func(base http.RoundTripper) http.RoundTripper {
		return &publicHost{base: base, location: srv.URL + "/secret"}
	}
	r := call(t, h, "http_request", map[string]any{"url": "http://public.example/start", "allow_private": true})
	if r.Body != "internal data" {
		t.Fatalf("opt-in: %d %q", r.Status, r.Body)
	}

	// Deny mode ignores allow_private.
	hd := tooltest.New(t, "http", tooltest.WithPrivateMode(config.PrivateDeny))
	hd.MustFail("http_request", map[string]any{"url": srv.URL, "allow_private": true}, "blocked")
}

func TestHTTPRequestGzip(t *testing.T) {
	h := tooltest.New(t, "http")
	payload := strings.Repeat("compressible text ", 2000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			io.WriteString(w, "client did not ask for gzip")
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, payload)
		zw.Close()
	}))
	defer srv.Close()
	// Transport-negotiated gzip and an explicit Accept-Encoding are both decoded.
	for _, hdr := range []map[string]string{{}, {"Accept-Encoding": "gzip"}} {
		r := call(t, h, "http_request", map[string]any{"url": srv.URL, "headers": hdr})
		if r.Body != payload || r.BodyEncoding != "text" {
			t.Fatalf("headers %v: body %d bytes %q...", hdr, len(r.Body), r.Body[:min(40, len(r.Body))])
		}
	}
	// Unknown encodings are flagged, not decoded.
	srvBr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Write([]byte{0x1b, 0x03, 0x00})
	}))
	defer srvBr.Close()
	r := call(t, h, "http_request", map[string]any{"url": srvBr.URL, "headers": map[string]string{"Accept-Encoding": "br"}})
	if len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "br") {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestHTTPRequestTruncationAndBinary(t *testing.T) {
	h := tooltest.New(t, "http")
	big := pattern(3 << 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/text" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(bytes.Repeat([]byte("a"), 5000))
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(big)
	}))
	defer srv.Close()
	r := call(t, h, "http_request", map[string]any{"url": srv.URL + "/text", "max_response_bytes": 1000})
	if !r.Truncated || len(r.Body) != 1000 || r.SizeBytes != 5000 || len(r.Warnings) == 0 {
		t.Fatalf("truncated=%v len=%d size=%d", r.Truncated, len(r.Body), r.SizeBytes)
	}
	r = call(t, h, "http_request", map[string]any{"url": srv.URL + "/bin"})
	if r.BodyEncoding != "base64" || !r.Truncated || r.SizeBytes != 3<<20 {
		t.Fatalf("binary: enc=%s truncated=%v size=%d", r.BodyEncoding, r.Truncated, r.SizeBytes)
	}
}

func TestHTTPRequestSlowBodyTimeout(t *testing.T) {
	h := tooltest.New(t, "http")
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < 100; i++ {
			io.WriteString(w, "tick\n")
			w.(http.Flusher).Flush()
			select {
			case <-stop:
				return
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	defer close(stop)
	start := time.Now()
	h.MustFail("http_request", map[string]any{"url": srv.URL, "timeout_seconds": 0.4}, "timed out")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func TestHTTPRequestSaveTo(t *testing.T) {
	h := tooltest.New(t, "http")
	data := pattern(2<<20 + 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Write(data)
	}))
	defer srv.Close()

	r := call(t, h, "http_request", map[string]any{"url": srv.URL + "/f.zip", "save_to": "dl/../f.zip"})
	if r.SavedTo == nil || r.SavedTo.SHA256 != sha(data) || r.SavedTo.SizeBytes != int64(len(data)) || r.Body != "" {
		t.Fatalf("saved %+v body %d", r.SavedTo, len(r.Body))
	}
	got, err := os.ReadFile(filepath.Join(h.WriteDir, "f.zip"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("file on disk: %v", err)
	}
	h.MustFail("http_request", map[string]any{"url": srv.URL + "/f.zip", "save_to": "f.zip"}, "overwrite=true")
	r = call(t, h, "http_request", map[string]any{"url": srv.URL + "/f.zip", "save_to": "f.zip", "overwrite": true})
	if r.SavedTo == nil {
		t.Fatal("overwrite")
	}
	// Outside the write directories, path traversal, and the read-only dir are denied.
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": filepath.Join(t.TempDir(), "x.bin")}, "outside the allowed write directories")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "../../escape.bin"}, "denied")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": filepath.Join(h.ReadDir, "x.bin")}, "outside the allowed write directories")
	// Download limit.
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "small.bin", "max_download_bytes": 1000}, "exceeds")
	if _, err := os.Stat(filepath.Join(h.WriteDir, "small.bin")); err == nil {
		t.Fatal("partial download left behind")
	}
	// Error responses are returned inline, not saved.
	r = call(t, h, "http_request", map[string]any{"url": srv.URL + "/missing", "save_to": "missing.bin"})
	if r.Status != 404 || r.SavedTo != nil || !strings.Contains(r.Body, "nope") || len(r.Warnings) == 0 {
		t.Fatalf("404: %+v", r)
	}
}

func TestHTTPFormRequest(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	r := call(t, h, "http_form_request", map[string]any{
		"url": srv.URL,
		"fields": []any{
			map[string]any{"name": "tag", "value": "x"},
			map[string]any{"name": "a b", "value": "1&2=3"},
			map[string]any{"name": "tag", "value": []any{"y", "z"}},
		},
	})
	e := decodeEcho(t, r)
	if e.Method != "POST" || e.Body != "tag=x&a+b=1%262%3D3&tag=y&tag=z" || e.Headers["Content-Type"][0] != "application/x-www-form-urlencoded" {
		t.Fatalf("%+v", e)
	}
	r = call(t, h, "http_form_request", map[string]any{"url": srv.URL, "method": "PUT", "fields": map[string]any{"b": "2", "a": []any{"1", "3"}}})
	if e := decodeEcho(t, r); e.Method != "PUT" || e.Body != "a=1&a=3&b=2" {
		t.Fatalf("%+v", e)
	}
	h.MustFail("http_form_request", map[string]any{"url": srv.URL, "fields": "nope"}, "fields must be")
}
