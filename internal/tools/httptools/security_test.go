package httptools_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/fileio/linktest"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// fakeHosts serves synthetic public hosts in-process: each host maps to a
// handler. Requests for other hosts go to the real (guarded) transport.
type fakeHosts struct {
	base  http.RoundTripper
	hosts map[string]http.Handler
}

func (f *fakeHosts) RoundTrip(req *http.Request) (*http.Response, error) {
	h, ok := f.hosts[req.URL.Hostname()]
	if !ok {
		return f.base.RoundTrip(req)
	}
	if req.Body == nil {
		req.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	io.Copy(io.Discard, req.Body)
	req.Body.Close()
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func hook(h *tooltest.Harness, hosts map[string]http.Handler) {
	h.Deps.HTTP.TransportHook = func(base http.RoundTripper) http.RoundTripper {
		return &fakeHosts{base: base, hosts: hosts}
	}
}

func redirectTo(target string, code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, target, code)
	})
}

// TestRedirectToPrivateBlockedAllTools checks every body-sending HTTP tool
// (and save_to downloads) refuses a public -> private redirect.
func TestRedirectToPrivateBlockedAllTools(t *testing.T) {
	h := tooltest.New(t, "http", tooltest.WithPrivateMode(config.PrivateOptIn))
	var mu sync.Mutex
	hits := 0
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "internal")
	}))
	defer internal.Close()
	f, _ := writeBig(t, h, "f.bin", 100000)

	for _, target := range []string{
		internal.URL + "/x",
		strings.Replace(internal.URL, "127.0.0.1", "localhost", 1) + "/x",
		strings.Replace(internal.URL, "127.0.0.1", "[::ffff:127.0.0.1]", 1) + "/x",
		"http://169.254.169.254/latest/meta-data/iam/",
		"http://10.0.0.1/admin",
	} {
		for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
			hook(h, map[string]http.Handler{"public.example": redirectTo(target, code)})
			cases := []struct {
				tool string
				args map[string]any
			}{
				{"http_request", map[string]any{"url": "http://public.example/a", "method": "PUT", "body_file": f}},
				{"http_request", map[string]any{"url": "http://public.example/a", "save_to": "dl.bin"}},
				{"http_form_request", map[string]any{"url": "http://public.example/a", "fields": map[string]any{"a": "b"}}},
				{"http_multipart_request", map[string]any{"url": "http://public.example/a", "parts": []any{map[string]any{"name": "f", "file": f}}}},
				{"http_upload", map[string]any{"url": "http://public.example/a", "file": f, "retries": 3, "retry_delay_seconds": 0.01}},
			}
			for _, c := range cases {
				r := h.MustFail(c.tool, c.args, "allow_private")
				if c.tool == "http_upload" && !strings.Contains(r.Text, "after 1 attempt(s)") {
					t.Errorf("blocked redirect was retried: %s", r.Text)
				}
			}
		}
	}
	if hits != 0 {
		t.Fatalf("the private server was reached %d times", hits)
	}
	if _, err := os.Stat(filepath.Join(h.WriteDir, "dl.bin")); err == nil {
		t.Fatal("blocked download left a file behind")
	}

	// Direct private targets fail the same way for every tool.
	h.MustFail("http_upload", map[string]any{"url": internal.URL, "file": f}, "allow_private")
	h.MustFail("http_multipart_request", map[string]any{"url": internal.URL, "fields": map[string]any{"a": "b"}}, "allow_private")

	// Deny lists apply to redirect targets too.
	hd := tooltest.New(t, "http", func(c *config.Config) { c.DenyHosts = []string{"*.internal.example"} })
	hook(hd, map[string]http.Handler{
		"public.example":      redirectTo("http://db.internal.example/", http.StatusFound),
		"db.internal.example": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "leak") }),
	})
	hd.MustFail("http_request", map[string]any{"url": "http://public.example/"}, "deny list")
}

// TestAuthorizationNotForwardedCrossHost checks credentials stay on the
// host they were given for.
func TestAuthorizationNotForwardedCrossHost(t *testing.T) {
	h := tooltest.New(t, "http")
	var got http.Header
	hook(h, map[string]http.Handler{
		"api.example":   redirectTo("http://other.example/landing", http.StatusFound),
		"other.example": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }),
	})
	call(t, h, "http_request", map[string]any{"url": "http://api.example/", "headers": map[string]string{"Authorization": "Bearer secret", "Cookie": "sid=1"}})
	if got == nil || got.Get("Authorization") != "" || got.Get("Cookie") != "" {
		t.Fatalf("credentials forwarded to another host: %v", got)
	}
	got = nil
	call(t, h, "http_request", map[string]any{"url": "http://api.example/", "auth": map[string]any{"type": "basic", "username": "u", "password": "p"}})
	if got == nil || got.Get("Authorization") != "" {
		t.Fatalf("auth forwarded to another host: %v", got)
	}
}

func TestEchoedRequestRedaction(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	secrets := []string{"s3cr3t-bearer", "cookie-val", "key-123", "pw-in-url", "tok-in-query", "proxy-pass"}
	u := strings.Replace(srv.URL, "http://", "http://user:pw-in-url@", 1) + "/p?access_token=tok-in-query&page=2"
	hdrs := map[string]string{
		"Authorization": "Bearer s3cr3t-bearer", "Cookie": "session=cookie-val", "X-Api-Key": "key-123",
		"Proxy-Authorization": "Basic proxy-pass", "X-Trace": "visible",
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"http_request", map[string]any{"url": u, "headers": hdrs, "body": "x", "include_request": true}},
		{"http_form_request", map[string]any{"url": u, "headers": hdrs, "fields": map[string]any{"a": "b"}, "include_request": true}},
		{"http_multipart_request", map[string]any{"url": u, "headers": hdrs, "fields": map[string]any{"a": "b"}, "include_request": true}},
	} {
		r := call(t, h, tc.tool, tc.args)
		if r.Request == nil {
			t.Fatalf("%s: no request echo", tc.tool)
		}
		raw, _ := jsonString(r.Request)
		for _, s := range secrets {
			if strings.Contains(raw, s) {
				t.Errorf("%s: echoed request contains %q: %s", tc.tool, s, raw)
			}
		}
		if r.Request.Headers["Authorization"] != "Bearer ***" || r.Request.Headers["X-Trace"] != "visible" || !strings.Contains(r.Request.URL, "page=2") {
			t.Errorf("%s: echo %+v", tc.tool, r.Request)
		}
		// The server still received the real credentials.
		if e := decodeEcho(t, r); e.Headers["Authorization"][0] != "Bearer s3cr3t-bearer" {
			t.Errorf("%s: server got %v", tc.tool, e.Headers["Authorization"])
		}
	}
}

// symlinkOrSkip creates a symlink or skips the test where the OS does not
// allow it (Windows without developer mode).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestFilePathTraversal(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.txt")
	os.WriteFile(secret, []byte("top secret"), 0o644)
	rel, err := filepath.Rel(h.ReadDir, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{secret, rel, "../out/../../" + filepath.Base(outsideDir) + "/secret.txt", "..\\..\\secret.txt", filepath.Join(h.ReadDir, "..", "..")} {
		h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": p}, "")
		h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p}, "")
		h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "f", "file": p}}}, "")
	}
	// A directory is not a file.
	h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": h.ReadDir}, "not a regular file")

	// save_to: traversal, absolute paths outside, and the read-only dir.
	for _, p := range []string{"../escape.bin", "sub/../../escape.bin", filepath.Join(outsideDir, "x.bin"), filepath.Join(h.ReadDir, "x.bin")} {
		h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": p}, "")
		h.MustFail("http_form_request", map[string]any{"url": srv.URL, "fields": map[string]any{"a": "b"}, "save_to": p}, "")
		h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "fields": map[string]any{"a": "b"}, "save_to": p}, "")
	}
	entries, _ := os.ReadDir(outsideDir)
	if len(entries) != 1 {
		t.Fatalf("files written outside the allowed directories: %v", entries)
	}
}

func TestSymlinkEscape(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.txt")
	os.WriteFile(secret, []byte("top secret"), 0o644)

	// Reads through a symlink that points outside are refused.
	link := filepath.Join(h.ReadDir, "link.txt")
	symlinkOrSkip(t, secret, link)
	for _, p := range []string{link, "link.txt"} {
		h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": p}, "outside the allowed read directories")
		h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p}, "outside the allowed read directories")
		h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "f", "file": p}}}, "outside the allowed read directories")
	}
	// A symlink to a file inside the allowed dirs is fine.
	inside := h.WriteInput("real.txt", []byte("ok"))
	symlinkOrSkip(t, inside, filepath.Join(h.ReadDir, "good.txt"))
	if e := decodeEcho(t, call(t, h, "http_request", map[string]any{"url": srv.URL, "body_file": "good.txt"})); e.Body != "ok" {
		t.Fatalf("inside symlink: %q", e.Body)
	}

	// Writes through a symlinked file or directory that points outside are refused,
	// with or without overwrite.
	wlink := filepath.Join(h.WriteDir, "out.txt")
	symlinkOrSkip(t, secret, wlink)
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "out.txt"}, "outside the allowed write directories")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "out.txt", "overwrite": true}, "outside the allowed write directories")
	dlink := filepath.Join(h.WriteDir, "dirlink")
	symlinkOrSkip(t, outsideDir, dlink)
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "dirlink/new.bin"}, "outside the allowed write directories")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": "../out/dirlink/secret.txt"}, "outside the allowed read directories")
	if b, _ := os.ReadFile(secret); string(b) != "top secret" {
		t.Fatalf("secret overwritten: %q", b)
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "new.bin")); err == nil {
		t.Fatal("file created outside the write directory")
	}
}

func TestSaveToOverwrite(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "v-"+r.URL.Query().Get("v"))
	}))
	defer srv.Close()
	target := filepath.Join(h.WriteDir, "keep.txt")
	os.WriteFile(target, []byte("original"), 0o644)

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"http_request", map[string]any{}},
		{"http_form_request", map[string]any{"fields": map[string]any{"a": "b"}}},
		{"http_multipart_request", map[string]any{"fields": map[string]any{"a": "b"}}},
	} {
		args := map[string]any{"url": srv.URL + "?v=1", "save_to": "keep.txt"}
		for k, v := range tc.args {
			args[k] = v
		}
		h.MustFail(tc.tool, args, "overwrite=true")
		if b, _ := os.ReadFile(target); string(b) != "original" {
			t.Fatalf("%s overwrote without overwrite=true: %q", tc.tool, b)
		}
	}
	r := call(t, h, "http_request", map[string]any{"url": srv.URL + "?v=2", "save_to": "keep.txt", "overwrite": true})
	if b, _ := os.ReadFile(target); string(b) != "v-2" || r.SavedTo == nil || r.SavedTo.SHA256 != sha([]byte("v-2")) {
		t.Fatalf("overwrite: %q %+v", b, r.SavedTo)
	}
	// No temp files are left behind.
	entries, _ := os.ReadDir(h.WriteDir)
	if len(entries) != 1 {
		t.Fatalf("write dir: %v", entries)
	}
}

func jsonString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// TestDirLinkEscape uses a directory link (a junction on Windows, which
// needs no privilege) pointing outside the allowed directories.
func TestDirLinkEscape(t *testing.T) {
	h := tooltest.New(t, "http")
	srv := echoServer(t)
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.txt")
	os.WriteFile(secret, []byte("top secret"), 0o644)

	if err := linktest.DirLink(outsideDir, filepath.Join(h.ReadDir, "jr")); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}
	if err := linktest.DirLink(outsideDir, filepath.Join(h.WriteDir, "jw")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"jr/secret.txt", filepath.Join(h.ReadDir, "jr", "secret.txt"), filepath.Join(h.WriteDir, "jw", "secret.txt")} {
		h.MustFail("http_request", map[string]any{"url": srv.URL, "body_file": p}, "outside the allowed read directories")
		h.MustFail("http_upload", map[string]any{"url": srv.URL, "file": p}, "outside the allowed read directories")
		h.MustFail("http_multipart_request", map[string]any{"url": srv.URL, "parts": []any{map[string]any{"name": "f", "file": p}}}, "outside the allowed read directories")
	}
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "jw/new.bin"}, "outside the allowed write directories")
	h.MustFail("http_request", map[string]any{"url": srv.URL, "save_to": "jw/secret.txt", "overwrite": true}, "outside the allowed write directories")
	if _, err := os.Stat(filepath.Join(outsideDir, "new.bin")); err == nil {
		t.Fatal("file created outside the write directory")
	}
	if b, _ := os.ReadFile(secret); string(b) != "top secret" {
		t.Fatalf("secret overwritten: %q", b)
	}

	// A link that stays inside the allowed directories keeps working.
	sub := filepath.Join(h.WriteDir, "data")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "ok.txt"), []byte("fine"), 0o644)
	if err := linktest.DirLink(sub, filepath.Join(h.WriteDir, "alias")); err != nil {
		t.Fatal(err)
	}
	if e := decodeEcho(t, call(t, h, "http_request", map[string]any{"url": srv.URL, "body_file": filepath.Join(h.WriteDir, "alias", "ok.txt")})); e.Body != "fine" {
		t.Fatalf("inside link: %q", e.Body)
	}
	r := call(t, h, "http_request", map[string]any{"url": srv.URL, "save_to": filepath.Join(h.WriteDir, "alias", "saved.json")})
	if r.SavedTo == nil {
		t.Fatal("save through inside link")
	}
	if _, err := os.Stat(filepath.Join(sub, "saved.json")); err != nil {
		t.Fatal(err)
	}
}
