package httptools_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// gotUpload is what the upload server saw on its latest request.
type gotUpload struct {
	Method        string
	Path          string
	EscapedPath   string
	RawQuery      string
	Header        http.Header
	ContentLength int64
	Chunked       bool
	Size          int64
	SHA256        string
}

type uploadServer struct {
	*httptest.Server
	mu    sync.Mutex
	reqs  []gotUpload
	fails []int // statuses to answer before succeeding
}

func newUploadServer(t *testing.T) *uploadServer {
	u := &uploadServer{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		g := gotUpload{
			Method: r.Method, Path: r.URL.Path, EscapedPath: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery,
			Header: r.Header.Clone(), ContentLength: r.ContentLength, Chunked: len(r.TransferEncoding) > 0,
			Size: n, SHA256: hex.EncodeToString(h.Sum(nil)),
		}
		u.mu.Lock()
		u.reqs = append(u.reqs, g)
		var status int
		if len(u.fails) > 0 {
			status, u.fails = u.fails[0], u.fails[1:]
		}
		u.mu.Unlock()
		if status != 0 {
			http.Error(w, "try again", status)
			return
		}
		w.Header().Set("ETag", `"`+g.SHA256[:16]+`"`)
		w.Header().Set("Location", "/stored/"+g.SHA256[:8])
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "stored")
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *uploadServer) requests() []gotUpload {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]gotUpload(nil), u.reqs...)
}

func (u *uploadServer) reset(fails ...int) {
	u.mu.Lock()
	u.reqs, u.fails = nil, fails
	u.mu.Unlock()
}

func (u *uploadServer) last(t *testing.T) gotUpload {
	t.Helper()
	rs := u.requests()
	if len(rs) == 0 {
		t.Fatal("server got no request")
	}
	return rs[len(rs)-1]
}

func upload(t *testing.T, h *tooltest.Harness, args map[string]any) types.TransferResult {
	t.Helper()
	var out types.TransferResult
	h.MustOK("http_upload", args).Decode(t, &out)
	return out
}

func TestUploadPutPostAndContentType(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := newUploadServer(t)
	p, sum := writeBig(t, h, "data.json", 3<<20+5)

	r := upload(t, h, map[string]any{"url": srv.URL + "/obj", "file": p})
	g := srv.last(t)
	if g.Method != "PUT" || g.SHA256 != sum || g.ContentLength != 3<<20+5 || g.Chunked {
		t.Fatalf("server got %+v", g)
	}
	if ct := g.Header.Get("Content-Type"); ct != mime.TypeByExtension(".json") {
		t.Fatalf("content type %q", ct)
	}
	if r.File.Name != "data.json" || r.File.SHA256 != sum || r.File.SizeBytes != 3<<20+5 || r.BytesTransferred != 3<<20+5 || r.Parts != 1 {
		t.Fatalf("result file %+v sent %d", r.File, r.BytesTransferred)
	}
	if r.Remote.Status != 201 || r.Remote.ETag != `"`+sum[:16]+`"` || r.Remote.Location != "/stored/"+sum[:8] || r.TimingMS.Total < 0 { // 0 is possible with a coarse clock
		t.Fatalf("remote %+v timing %v", r.Remote, r.TimingMS)
	}
	if r.Response == nil || r.Response.Body != "stored" || len(r.Warnings) != 0 {
		t.Fatalf("response %+v warnings %v", r.Response, r.Warnings)
	}

	// POST, relative path, explicit content type and extra headers.
	r = upload(t, h, map[string]any{
		"url": srv.URL + "/form", "file": "data.json", "method": "post",
		"content_type": "application/x-custom", "headers": map[string]string{"X-Meta": "1", "Content-Disposition": `attachment; filename="d.json"`},
	})
	g = srv.last(t)
	if g.Method != "POST" || g.Header.Get("Content-Type") != "application/x-custom" || g.Header.Get("X-Meta") != "1" || g.Header.Get("Content-Disposition") == "" || g.SHA256 != sum {
		t.Fatalf("server got %+v", g)
	}
	if r.File.ContentType != "application/x-custom" {
		t.Fatalf("file content type %q", r.File.ContentType)
	}

	// Unknown extension: the content is sniffed.
	png := h.WriteInput("image.nkx2", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
	r = upload(t, h, map[string]any{"url": srv.URL + "/img", "file": png})
	if ct := srv.last(t).Header.Get("Content-Type"); ct != "image/png" || r.File.ContentType != "image/png" {
		t.Fatalf("sniffed %q / %q", ct, r.File.ContentType)
	}
	// An empty file is sent with Content-Length 0.
	empty := h.WriteInput("empty.txt", nil)
	r = upload(t, h, map[string]any{"url": srv.URL + "/empty", "file": empty})
	if g := srv.last(t); g.Size != 0 || g.ContentLength != 0 || r.File.SHA256 != sha(nil) {
		t.Fatalf("empty: %+v %+v", g, r.File)
	}

	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p, "method": "DELETE"}, "PUT or POST")
	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": "nope.bin"}, "")
	h.MustFail("http_upload", map[string]any{"url": "ftp://files.example/x", "file": p}, "scheme")
}

func TestUploadStreams(t *testing.T) {
	h := tooltest.New(t, "http", smallCaps)
	srv := newUploadServer(t)
	const size = 64 << 20
	p, sum := writeBig(t, h, "huge.bin", size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r := upload(t, h, map[string]any{"url": srv.URL, "file": p, "checksum": "sha256"})
	runtime.ReadMemStats(&after)
	if g := srv.last(t); g.SHA256 != sum || r.File.SHA256 != sum {
		t.Fatal("hash mismatch")
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated %d KiB while uploading %d MiB", alloc>>10, size>>20)
	if alloc > 16<<20 {
		t.Fatalf("upload allocated %d MiB for a %d MiB file; it must be streamed", alloc>>20, size>>20)
	}
}

func TestUploadChecksums(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := newUploadServer(t)
	data := pattern(200000)
	p := h.WriteInput("c.bin", data)
	m := md5.Sum(data)
	s := sha256.Sum256(data)

	r := upload(t, h, map[string]any{"url": srv.URL, "file": p, "checksum": "md5"})
	if got := srv.last(t).Header.Get("Content-MD5"); got != base64.StdEncoding.EncodeToString(m[:]) {
		t.Fatalf("Content-MD5 %q", got)
	}
	if cs, _ := r.Meta["checksum"].(map[string]any); cs["algorithm"] != "md5" || cs["header"] != "Content-MD5" {
		t.Fatalf("meta %v", r.Meta)
	}
	upload(t, h, map[string]any{"url": srv.URL, "file": p, "checksum": "SHA-256"})
	if got := srv.last(t).Header.Get("X-Amz-Checksum-Sha256"); got != base64.StdEncoding.EncodeToString(s[:]) {
		t.Fatalf("x-amz-checksum-sha256 %q", got)
	}
	upload(t, h, map[string]any{"url": srv.URL, "file": p, "checksum": "sha256", "checksum_header": "X-Checksum", "checksum_encoding": "hex"})
	if got := srv.last(t).Header.Get("X-Checksum"); got != hex.EncodeToString(s[:]) {
		t.Fatalf("X-Checksum %q", got)
	}
	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p, "checksum": "crc32"}, "md5 or sha256")
	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p, "checksum": "md5", "checksum_encoding": "b32"}, "base64 or hex")
}

func TestUploadRetries(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := newUploadServer(t)
	p, sum := writeBig(t, h, "r.bin", 1<<20)

	// 503, 500, 429 then success: the file is re-read and fully re-sent each attempt.
	srv.reset(503, 500, 429)
	r := upload(t, h, map[string]any{"url": srv.URL, "file": p, "retries": 3, "retry_delay_seconds": 0.01})
	rs := srv.requests()
	if len(rs) != 4 || r.Remote.Status != 201 || r.Meta["attempts"] != float64(4) {
		t.Fatalf("requests %d status %d meta %v", len(rs), r.Remote.Status, r.Meta)
	}
	for i, g := range rs {
		if g.SHA256 != sum || g.ContentLength != 1<<20 {
			t.Fatalf("attempt %d: server got %d bytes, hash ok=%v", i+1, g.Size, g.SHA256 == sum)
		}
	}
	if r.File.SHA256 != sum || r.BytesTransferred != 1<<20 || len(r.Warnings) != 3 {
		t.Fatalf("file %+v sent %d warnings %v", r.File, r.BytesTransferred, r.Warnings)
	}

	// Retries exhausted: the last error status is the result, flagged in warnings.
	srv.reset(502, 502, 502)
	r = upload(t, h, map[string]any{"url": srv.URL, "file": p, "retries": 1, "retry_delay_seconds": 0.01})
	if len(srv.requests()) != 2 || r.Remote.Status != 502 || r.Meta["attempts"] != float64(2) {
		t.Fatalf("exhausted: %d requests, status %d", len(srv.requests()), r.Remote.Status)
	}
	if !strings.Contains(strings.Join(r.Warnings, "|"), "HTTP 502") {
		t.Fatalf("warnings %v", r.Warnings)
	}

	// No retries by default; 4xx (other than 408/429) are never retried.
	srv.reset(503)
	if r = upload(t, h, map[string]any{"url": srv.URL, "file": p}); len(srv.requests()) != 1 || r.Remote.Status != 503 {
		t.Fatalf("default: %d requests status %d", len(srv.requests()), r.Remote.Status)
	}
	srv.reset(403)
	if r = upload(t, h, map[string]any{"url": srv.URL, "file": p, "retries": 3, "retry_delay_seconds": 0.01}); len(srv.requests()) != 1 || r.Remote.Status != 403 {
		t.Fatalf("403: %d requests status %d", len(srv.requests()), r.Remote.Status)
	}

	// Network errors are retried too, then reported.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	h.MustFail("http_upload", map[string]any{"url": deadURL, "file": p, "retries": 2, "retry_delay_seconds": 0.01}, "after 3 attempt(s)")

	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p, "retries": 11}, "retries must be between")
}

func TestUploadSizeLimit(t *testing.T) {
	h := tooltest.New(t, "http", func(c *config.Config) { c.DefaultUploadBytes = 1 << 20 })
	srv := newUploadServer(t)
	ok, _ := writeBig(t, h, "ok.bin", 1<<20)
	over, _ := writeBig(t, h, "over.bin", 1<<20+1)
	upload(t, h, map[string]any{"url": srv.URL, "file": ok})
	srv.reset()
	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": over}, "above the 1048576 byte upload limit")
	if len(srv.requests()) != 0 {
		t.Fatal("an oversized file was sent")
	}
}

func TestUploadPresignedURLs(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := newUploadServer(t)
	p := h.WriteInput("report final.pdf", []byte("%PDF-1.4 test"))

	// S3 SigV4 presigned URL: path escaping and the query string are sent byte for byte.
	q := "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20261110%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20261110T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=content-type%3Bhost" +
		"&x-id=PutObject&X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	path := "/my-bucket/dir%2Fsub/report%20final.pdf"
	r := upload(t, h, map[string]any{"url": srv.URL + path + "?" + q, "file": p, "content_type": "application/pdf"})
	g := srv.last(t)
	if g.RawQuery != q || g.EscapedPath != path {
		t.Fatalf("presigned URL changed:\n path %s\n  got %s\nquery %s\n  got %s", path, g.EscapedPath, q, g.RawQuery)
	}
	if r.Meta["presigned"] != "s3" || g.Header.Get("Content-Type") != "application/pdf" || g.Header.Get("Authorization") != "" {
		t.Fatalf("meta %v headers %v", r.Meta, g.Header)
	}

	// Azure SAS: x-ms-blob-type is added for Put Blob.
	sas := "sv=2024-11-04&ss=b&srt=o&sp=cw&se=2026-11-11T00%3A00%3A00Z&sig=abc%2Bdef%2F%3D"
	r = upload(t, h, map[string]any{"url": srv.URL + "/container/blob.pdf?" + sas, "file": p})
	g = srv.last(t)
	if g.RawQuery != sas || g.Header.Get("X-Ms-Blob-Type") != "BlockBlob" || r.Meta["presigned"] != "azure" || len(r.Warnings) == 0 {
		t.Fatalf("azure: query %q headers %v meta %v warnings %v", g.RawQuery, g.Header, r.Meta, r.Warnings)
	}
	// An explicit blob type is kept.
	upload(t, h, map[string]any{"url": srv.URL + "/container/blob.pdf?" + sas, "file": p, "headers": map[string]string{"x-ms-blob-type": "AppendBlob"}})
	if got := srv.last(t).Header.Get("X-Ms-Blob-Type"); got != "AppendBlob" {
		t.Fatalf("blob type %q", got)
	}

	// GCS signed URL, and auth on a presigned URL is flagged.
	gcs := "X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=svc%40proj.iam.gserviceaccount.com%2F20261110%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Signature=beef"
	r = upload(t, h, map[string]any{"url": srv.URL + "/b/o?" + gcs, "file": p, "auth": map[string]any{"type": "bearer", "token": "t"}})
	if srv.last(t).RawQuery != gcs || r.Meta["presigned"] != "gcs" || !strings.Contains(strings.Join(r.Warnings, "|"), "presigned") {
		t.Fatalf("gcs: meta %v warnings %v", r.Meta, r.Warnings)
	}
}
