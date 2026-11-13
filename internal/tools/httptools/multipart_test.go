package httptools_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// gotPart is one part as the server parsed it.
type gotPart struct {
	Name        string
	Filename    string
	HasFilename bool
	ContentType string
	Headers     map[string]string
	Size        int64
	SHA256      string
	Text        string // first 256 bytes
}

// gotMultipart is a whole request as the server saw it.
type gotMultipart struct {
	Method        string
	ContentType   string
	Boundary      string
	ContentLength int64
	Chunked       bool
	RawBytes      int64
	Tail          string
	Head          string
	Parts         []gotPart
	Err           string
}

// countingTail counts bytes and keeps the first and last few bytes.
type countingTail struct {
	n    int64
	head []byte
	tail []byte
}

func (c *countingTail) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if len(c.head) < 256 {
		c.head = append(c.head, p[:min(len(p), 256-len(c.head))]...)
	}
	// Keep the last 256 bytes without allocating per write.
	if c.tail == nil {
		c.tail = make([]byte, 0, 512)
	}
	if len(p) >= 256 {
		c.tail = append(c.tail[:0], p[len(p)-256:]...)
	} else {
		if len(c.tail)+len(p) > 512 {
			keep := c.tail[len(c.tail)-256:]
			c.tail = c.tail[:copy(c.tail, keep)]
		}
		c.tail = append(c.tail, p...)
	}
	return len(p), nil
}

// multipartServer parses multipart bodies in a streaming fashion and
// records every part (hashing contents instead of keeping them).
func multipartServer(t *testing.T) (*httptest.Server, func() gotMultipart) {
	var mu sync.Mutex
	var last gotMultipart
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := gotMultipart{Method: r.Method, ContentType: r.Header.Get("Content-Type"), ContentLength: r.ContentLength, Chunked: len(r.TransferEncoding) > 0}
		ct := &countingTail{}
		body := io.TeeReader(r.Body, ct)
		mt, params, err := mime.ParseMediaType(g.ContentType)
		if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
			g.Err = "bad content type " + g.ContentType
		} else {
			g.Boundary = params["boundary"]
			mr := multipart.NewReader(body, g.Boundary)
			for {
				p, err := mr.NextPart()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					g.Err = err.Error()
					break
				}
				gp := gotPart{Name: p.FormName(), ContentType: p.Header.Get("Content-Type"), Headers: map[string]string{}}
				_, cdParams, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
				gp.Filename, gp.HasFilename = cdParams["filename"]
				for k := range p.Header {
					gp.Headers[k] = p.Header.Get(k)
				}
				h := sha256.New()
				var head bytes.Buffer
				n, _ := io.Copy(io.MultiWriter(h, &limitWriter{&head, 256}), p)
				gp.Size, gp.SHA256, gp.Text = n, hex.EncodeToString(h.Sum(nil)), head.String()
				g.Parts = append(g.Parts, gp)
			}
		}
		io.Copy(io.Discard, body)
		g.RawBytes, g.Tail, g.Head = ct.n, string(ct.tail), string(ct.head)
		mu.Lock()
		last = g
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"parts": len(g.Parts), "err": g.Err})
	}))
	t.Cleanup(srv.Close)
	return srv, func() gotMultipart {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

type limitWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		l.w.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// smallCaps lowers the inline base64 cap so the test file is far above it.
func smallCaps(c *config.Config) {
	c.MaxInlineBase64Bytes = 64 << 10
	c.DefaultResponseBytes = 64 << 10
}

func TestMultipartFieldsFilesAndHeaders(t *testing.T) {
	h := tooltest.New(t, "http", smallCaps)
	srv, last := multipartServer(t)

	bigPath, bigSum := writeBig(t, h, "big.bin", 5<<20+123) // far above the 64 KiB inline cap
	a := h.WriteInput("a.txt", []byte("alpha file\n"))
	h.WriteInput("b.json", []byte(`{"b":true}`))
	png := h.WriteInput("pixel.nkx1", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
	bin := []byte{0, 1, 2, 3, 0xfe, 0xff}

	r := call(t, h, "http_multipart_request", map[string]any{
		"url": srv.URL + "/upload?x=1",
		"fields": []any{
			map[string]any{"name": "title", "value": "hello world"},
			map[string]any{"name": "tag", "value": "one"},
			map[string]any{"name": "tag", "value": []any{"two", "three"}},
		},
		"parts": []any{
			map[string]any{"name": "note", "value": "a text part", "headers": map[string]string{"X-Part": "note", "Content-Disposition": "evil"}},
			map[string]any{"name": "meta", "json": map[string]any{"k": []any{1, 2}}},
			map[string]any{"name": "files", "file": a},
			map[string]any{"name": "files", "file": "b.json", "filename": `ren"amed ü.json`, "content_type": "application/vnd.test+json"},
			map[string]any{"name": "files", "file": bigPath, "headers": map[string]string{"X-Big": "yes"}},
			map[string]any{"name": "image", "file": png},
			map[string]any{"name": "blob", "base64": base64.StdEncoding.EncodeToString(bin)},
			map[string]any{"name": "blob2", "base64": base64.StdEncoding.EncodeToString(bin), "filename": "raw.bin", "content_type": "application/x-raw"},
		},
		"headers":         map[string]string{"Content-Type": "multipart/form-data; boundary=wrong", "Authorization": "Bearer top-secret", "X-Api-Key": "k-123"},
		"include_request": true,
	})
	g := last()
	if g.Err != "" || r.Status != 200 {
		t.Fatalf("server: %s (status %d)", g.Err, r.Status)
	}
	if g.Method != "POST" || g.Chunked || g.ContentLength != g.RawBytes || g.ContentLength <= 5<<20 {
		t.Fatalf("method %s chunked %v content-length %d raw %d", g.Method, g.Chunked, g.ContentLength, g.RawBytes)
	}
	// The boundary in the header delimits the body and the closing delimiter ends it.
	if g.Boundary == "wrong" || !strings.HasPrefix(g.Head, "--"+g.Boundary+"\r\n") || !strings.HasSuffix(g.Tail, "\r\n--"+g.Boundary+"--\r\n") {
		t.Fatalf("boundary %q head %q tail %q", g.Boundary, g.Head[:min(80, len(g.Head))], g.Tail)
	}

	want := []struct {
		name, filename string
		hasFilename    bool
		ct, text, sum  string
		size           int64
	}{
		{"title", "", false, "", "hello world", "", 11},
		{"tag", "", false, "", "one", "", 3},
		{"tag", "", false, "", "two", "", 3},
		{"tag", "", false, "", "three", "", 5},
		{"note", "", false, "", "a text part", "", 11},
		{"meta", "", false, "application/json", `{"k":[1,2]}`, "", 11},
		{"files", "a.txt", true, mime.TypeByExtension(".txt"), "alpha file\n", "", 11},
		{"files", `ren"amed ü.json`, true, "application/vnd.test+json", `{"b":true}`, "", 10},
		{"files", "big.bin", true, "application/octet-stream", "", bigSum, 5<<20 + 123},
		{"image", "pixel.nkx1", true, "image/png", "", "", 16},
		{"blob", "", false, "application/octet-stream", string(bin), "", 6},
		{"blob2", "raw.bin", true, "application/x-raw", string(bin), "", 6},
	}
	if len(g.Parts) != len(want) {
		t.Fatalf("got %d parts: %+v", len(g.Parts), g.Parts)
	}
	for i, w := range want {
		p := g.Parts[i]
		if p.Name != w.name || p.Filename != w.filename || p.HasFilename != w.hasFilename || p.ContentType != w.ct || p.Size != w.size {
			t.Errorf("part %d: got %+v\nwant %+v", i, p, w)
		}
		if w.text != "" && p.Text != w.text {
			t.Errorf("part %d text %q want %q", i, p.Text, w.text)
		}
		if w.sum != "" && p.SHA256 != w.sum {
			t.Errorf("part %d sha256 mismatch", i)
		}
	}
	if g.Parts[4].Headers["X-Part"] != "note" || !strings.HasPrefix(g.Parts[4].Headers["Content-Disposition"], "form-data") {
		t.Errorf("part headers %v", g.Parts[4].Headers)
	}
	if g.Parts[8].Headers["X-Big"] != "yes" {
		t.Errorf("big part headers %v", g.Parts[8].Headers)
	}

	// Result: every file with name, size and sha256; echo is redacted and has no contents.
	if len(r.UploadedFiles) != 4 {
		t.Fatalf("uploaded %+v", r.UploadedFiles)
	}
	if f := r.UploadedFiles[2]; f.Name != "big.bin" || f.SizeBytes != 5<<20+123 || f.SHA256 != bigSum {
		t.Fatalf("big file info %+v", f)
	}
	for _, f := range r.UploadedFiles {
		if len(f.SHA256) != 64 || f.SizeBytes == 0 {
			t.Errorf("file info %+v", f)
		}
	}
	rq := r.Request
	if rq == nil || rq.Body == nil || rq.Body.Kind != "multipart" || rq.Body.SizeBytes != g.ContentLength || len(rq.Body.Files) != 4 {
		t.Fatalf("echo %+v", rq)
	}
	if rq.Headers["Authorization"] != "Bearer ***" || rq.Headers["X-Api-Key"] != "***" {
		t.Fatalf("echo headers not redacted: %v", rq.Headers)
	}
	if !strings.Contains(rq.Headers["Content-Type"], g.Boundary) {
		t.Fatalf("echo content type %q", rq.Headers["Content-Type"])
	}
	if raw := string(h.MustOK("http_multipart_request", map[string]any{"url": srv.URL, "fields": map[string]any{"a": "b"}, "headers": map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, "include_request": true}).Raw); strings.Contains(raw, "dXNlcjpwYXNz") {
		t.Fatalf("credentials echoed: %s", raw)
	}
}

func TestMultipartObjectFieldsAndMethod(t *testing.T) {
	h := tooltest.New(t, "http")
	srv, last := multipartServer(t)
	call(t, h, "http_multipart_request", map[string]any{
		"url":    srv.URL,
		"method": "put",
		"fields": map[string]any{"b": "2", "a": []any{"1", "3"}},
	})
	g := last()
	if g.Method != "PUT" || len(g.Parts) != 3 || g.Parts[0].Name != "a" || g.Parts[1].Text != "3" || g.Parts[2].Name != "b" {
		t.Fatalf("%+v", g)
	}
	// An empty file is a valid part.
	empty := h.WriteInput("empty.txt", nil)
	r := call(t, h, "http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "f", "file": empty}}})
	if g := last(); len(g.Parts) != 1 || g.Parts[0].Size != 0 || g.Parts[0].Filename != "empty.txt" || g.ContentLength != g.RawBytes {
		t.Fatalf("empty file: %+v", g)
	}
	if len(r.UploadedFiles) != 1 || r.UploadedFiles[0].SHA256 != sha(nil) {
		t.Fatalf("empty file info %+v", r.UploadedFiles)
	}
}

func TestMultipartStreamsLargeFiles(t *testing.T) {
	h := tooltest.New(t, "http", smallCaps)
	srv, last := multipartServer(t)
	const size = 48 << 20
	p, sum := writeBig(t, h, "huge.bin", size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r := call(t, h, "http_multipart_request", map[string]any{
		"url":   srv.URL,
		"parts": []any{map[string]any{"name": "a", "file": p}, map[string]any{"name": "b", "file": p}},
	})
	runtime.ReadMemStats(&after)
	g := last()
	if len(g.Parts) != 2 || g.Parts[0].SHA256 != sum || g.Parts[1].SHA256 != sum || g.Parts[1].Size != size {
		t.Fatalf("server parts %+v err %s", g.Parts, g.Err)
	}
	if g.Chunked || g.ContentLength != g.RawBytes {
		t.Fatalf("content-length %d raw %d chunked %v", g.ContentLength, g.RawBytes, g.Chunked)
	}
	if len(r.UploadedFiles) != 2 || r.UploadedFiles[1].SHA256 != sum {
		t.Fatalf("uploaded %+v", r.UploadedFiles)
	}
	// 96 MiB went over the wire; buffering even one file would allocate at least 48 MiB.
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated %d KiB while sending %d MiB", alloc>>10, 2*size>>20)
	if alloc > 24<<20 {
		t.Fatalf("multipart upload allocated %d MiB for %d MiB of files; files must be streamed", alloc>>20, 2*size>>20)
	}
}

func TestMultipartLimitsAndErrors(t *testing.T) {
	h := tooltest.New(t, "http", smallCaps, func(c *config.Config) { c.DefaultUploadBytes = 1 << 20 })
	srv, _ := multipartServer(t)
	tooBig := base64.StdEncoding.EncodeToString(make([]byte, 40<<10))
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{
		map[string]any{"name": "a", "base64": tooBig}, map[string]any{"name": "b", "base64": tooBig},
	}}, "inline base64 parts exceed")
	big, _ := writeBig(t, h, "over.bin", 1<<20+1)
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "f", "file": big}}}, "upload limit")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL}, "at least one field or part")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "x", "value": "a", "file": "a.txt"}}}, "exactly one of")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"value": "a"}}}, "name")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "x", "base64": "!!notbase64"}}}, "base64")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "x", "file": "missing.txt"}}}, "")

	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "x", "file": outside}}}, "outside the allowed read directories")
	h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "x", "file": "../../" + filepath.Base(filepath.Dir(outside)) + "/secret.txt"}}}, "")
}

func TestMultipartRedirect307ResendsBody(t *testing.T) {
	h := tooltest.New(t, "http")
	srv, last := multipartServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, srv.URL+"/final", http.StatusTemporaryRedirect)
	})
	front := httptest.NewServer(mux)
	defer front.Close()
	p, sum := writeBig(t, h, "r.bin", 300000)
	r := call(t, h, "http_multipart_request", map[string]any{"url": front.URL + "/start", "parts": []any{map[string]any{"name": "f", "file": p}}})
	if g := last(); r.Status != 200 || len(g.Parts) != 1 || g.Parts[0].SHA256 != sum || len(r.Redirects) != 1 {
		t.Fatalf("status %d parts %+v redirects %v", r.Status, g.Parts, r.Redirects)
	}
}
