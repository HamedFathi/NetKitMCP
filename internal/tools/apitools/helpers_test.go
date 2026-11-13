package apitools_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/HamedFathi/NetKitMCP/internal/tools/apitools" // registers the tools
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// group is the tool group the apitools family registers in.
const group = "http"

func newHarness(t *testing.T, opts ...tooltest.Option) *tooltest.Harness {
	t.Helper()
	return tooltest.New(t, group, opts...)
}

// server starts an httptest server that is closed at the end of the test.
func server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// timed runs f and fails the test if it takes longer than max (every call
// must end on its own).
func timed(t *testing.T, max time.Duration, f func()) time.Duration {
	t.Helper()
	start := time.Now()
	f()
	d := time.Since(start)
	if d > max {
		t.Fatalf("call took %s, expected under %s", d, max)
	}
	return d
}

func decode[T any](t *testing.T, r *tooltest.Result) T {
	t.Helper()
	var v T
	r.Decode(t, &v)
	return v
}

func stream(t *testing.T, h *tooltest.Harness, tool string, args map[string]any) types.StreamResult {
	t.Helper()
	return decode[types.StreamResult](t, h.MustOK(tool, args))
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// pattern returns n deterministic pseudo-random bytes.
func pattern(n int) []byte {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

func testdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func mustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Fatalf("expected %q in:\n%s", sub, s)
		}
	}
}

func mustNotContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Fatalf("did not expect %q in:\n%s", sub, s)
		}
	}
}
