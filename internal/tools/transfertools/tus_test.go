package transfertools_test

import (
	"bytes"
	"golang.org/x/exp/slog"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/tus/tusd/v2/pkg/filestore"
	tushandler "github.com/tus/tusd/v2/pkg/handler"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/transfertools"
)

type tusServer struct {
	*httptest.Server
	dir string
	// killPatch, when > 0, makes the Nth PATCH request (1-based) store only
	// half of its body and then drop the connection without a response.
	killPatch atomic.Int32
	patches   atomic.Int32
}

func newTusServer(t *testing.T) *tusServer {
	t.Helper()
	dir := t.TempDir()
	store := filestore.New(dir)
	composer := tushandler.NewStoreComposer()
	store.UseIn(composer)
	h, err := tushandler.NewHandler(tushandler.Config{
		BasePath:      "/files/",
		StoreComposer: composer,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := &tusServer{dir: dir}
	ts.Server = httptest.NewServer(http.StripPrefix("/files/", ts.wrap(h)))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *tusServer) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			n := ts.patches.Add(1)
			if k := ts.killPatch.Load(); k > 0 && n == k {
				ts.killPatch.Store(0)
				half := r.ContentLength / 2
				r2 := r.Clone(r.Context())
				r2.Body = io.NopCloser(io.LimitReader(r.Body, half))
				r2.ContentLength = half
				r2.Header.Set("Content-Length", strconv.FormatInt(half, 10))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r2)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (ts *tusServer) stored(t *testing.T, uploadURL string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ts.dir, path.Base(uploadURL)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTusUploadChunked(t *testing.T) {
	ts := newTusServer(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 3<<20+12345)
	file := h.WriteInput("video.bin", data)

	for _, cwu := range []bool{false, true} {
		r := h.MustOK("tus_upload", map[string]any{
			"url": ts.URL + "/files/", "file": file, "chunk_size": 1 << 20,
			"creation_with_upload": cwu, "metadata": map[string]string{"owner": "tests"},
		})
		var out transferOut
		r.Decode(t, &out)
		if out.File.SHA256 != sha(data) || out.File.SizeBytes != int64(len(data)) || out.File.Name != "video.bin" {
			t.Fatalf("file info: %+v", out.File)
		}
		if out.BytesTransferred != int64(len(data)) || out.Parts != 4 || out.ResumedFrom != 0 {
			t.Fatalf("transfer: bytes=%d parts=%d resumed=%d", out.BytesTransferred, out.Parts, out.ResumedFrom)
		}
		if out.Remote.Location == "" || out.Meta["upload_url"] != out.Remote.Location {
			t.Fatalf("missing upload url: %+v", out.Remote)
		}
		if got := ts.stored(t, out.Remote.Location); !bytes.Equal(got, data) {
			t.Fatalf("stored content differs (%d bytes)", len(got))
		}
		info, err := os.ReadFile(filepath.Join(ts.dir, path.Base(out.Remote.Location)+".info"))
		if err != nil || !bytes.Contains(info, []byte(`"filename":"video.bin"`)) || !bytes.Contains(info, []byte(`"owner":"tests"`)) {
			t.Fatalf("metadata not stored: %s %v", info, err)
		}
		srv, _ := out.Meta["server"].(map[string]any)
		if srv["discovered"] != true {
			t.Fatalf("OPTIONS discovery failed: %v", out.Meta)
		}
	}
}

func TestTusRetryWithinCall(t *testing.T) {
	ts := newTusServer(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 3<<20)
	file := h.WriteInput("a.bin", data)
	ts.killPatch.Store(2)
	r := h.MustOK("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": file, "chunk_size": 1 << 20, "max_retries": 2})
	var out transferOut
	r.Decode(t, &out)
	if out.Meta["retries"].(float64) != 1 {
		t.Fatalf("expected one retry: %v", out.Meta)
	}
	if out.File.SHA256 != sha(data) || !bytes.Equal(ts.stored(t, out.Remote.Location), data) {
		t.Fatal("content mismatch after retry")
	}
}

var uploadURLRe = regexp.MustCompile(`upload_url="([^"]+)"`)

func TestTusResumeAfterInterruption(t *testing.T) {
	ts := newTusServer(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 4<<20+7)
	file := h.WriteInput("big.bin", data)
	ts.killPatch.Store(2)
	r := h.MustFail("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": file, "chunk_size": 1 << 20, "max_retries": 0}, "upload_url=")
	m := uploadURLRe.FindStringSubmatch(r.Text)
	if m == nil {
		t.Fatalf("no upload_url in error: %s", r.Text)
	}
	r = h.MustOK("tus_upload", map[string]any{"upload_url": m[1], "file": file, "chunk_size": 1 << 20})
	var out transferOut
	r.Decode(t, &out)
	// First chunk (1 MiB) plus half of the second were stored before the drop.
	want := int64(1<<20 + 1<<19)
	if out.ResumedFrom != want {
		t.Fatalf("resumed_from = %d, want %d", out.ResumedFrom, want)
	}
	if out.BytesTransferred != int64(len(data))-want {
		t.Fatalf("bytes_transferred = %d", out.BytesTransferred)
	}
	if out.File.SHA256 != sha(data) {
		t.Fatalf("sha256 must cover the whole file")
	}
	if !bytes.Equal(ts.stored(t, m[1]), data) {
		t.Fatal("stored content differs after resume")
	}

	// Resuming with a different file is refused.
	other := h.WriteInput("other.bin", data[:100])
	h.MustFail("tus_upload", map[string]any{"upload_url": m[1], "file": other}, "different file")
}

func TestTusEmptyFileAndChecksumWarning(t *testing.T) {
	ts := newTusServer(t)
	h := tooltest.New(t, "transfer")
	file := h.WriteInput("empty.txt", nil)
	r := h.MustOK("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": file, "checksum": true})
	var out transferOut
	r.Decode(t, &out)
	if out.File.SizeBytes != 0 || out.File.SHA256 != sha(nil) || out.Remote.Location == "" {
		t.Fatalf("unexpected: %+v", out)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("expected a warning that checksums are unsupported by the server")
	}
}

func TestTusSecurity(t *testing.T) {
	ts := newTusServer(t)
	h := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateOptIn))
	file := h.WriteInput("a.bin", []byte("hello"))
	h.MustFail("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": file}, "blocked")
	h.MustOK("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": file, "allow_private": true})
	// Files outside the allowed read directories are refused.
	outside := filepath.Join(filepath.Dir(h.ReadDir), "secret.bin")
	os.WriteFile(outside, []byte("x"), 0o644)
	h.MustFail("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": "../secret.bin", "allow_private": true}, "outside")
	h.MustFail("tus_upload", map[string]any{"url": ts.URL + "/files/", "file": outside, "allow_private": true}, "outside")
}
