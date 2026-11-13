package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func testFactory(t *testing.T, mut func(*config.Config)) *Factory {
	t.Helper()
	cfg := config.Default()
	cfg.PrivateMode = config.PrivateAllow
	if mut != nil {
		mut(cfg)
	}
	files, err := fileio.NewPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Factory{Cfg: cfg, Guard: netguard.New(cfg), Files: files, Auth: auth.NewManager()}
}

func TestReadResponseClampsMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()
	f := testFactory(t, func(c *config.Config) { c.DefaultResponseBytes, c.MaxResponseBytes = 500, 1000 })

	get := func(opts types.HTTPOptions, ro ReadOptions) *types.HTTPResponse {
		t.Helper()
		c, err := f.New(opts, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
		out, err := c.Do(req, ro)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		opts types.HTTPOptions
		ro   ReadOptions
		want int
	}{
		{"defaults", types.HTTPOptions{}, ReadOptions{}, 500},
		{"per-call option", types.HTTPOptions{MaxResponseBytes: 800}, ReadOptions{}, 800},
		{"option above ceiling", types.HTTPOptions{MaxResponseBytes: 1 << 30}, ReadOptions{}, 1000},
		{"read option", types.HTTPOptions{}, ReadOptions{MaxBytes: 700}, 700},
		{"read option above ceiling", types.HTTPOptions{}, ReadOptions{MaxBytes: 1 << 30}, 1000},
	} {
		out := get(tc.opts, tc.ro)
		if len(out.Body) != tc.want || !out.Truncated || out.SizeBytes != 5000 {
			t.Errorf("%s: body %d bytes (want %d), truncated %v, size %d", tc.name, len(out.Body), tc.want, out.Truncated, out.SizeBytes)
		}
	}
}

func TestSameOrSubdomain(t *testing.T) {
	for _, c := range []struct {
		host, origin string
		want         bool
	}{
		{"api.example.com", "api.example.com", true},
		{"API.example.com", "api.example.com", true},
		{"v2.api.example.com", "api.example.com", true},
		{"example.com", "api.example.com", false},
		{"evilapi.example.com", "api.example.com", false},
		{"other.example", "api.example.com", false},
		{"1.127.0.0.1", "127.0.0.1", false},
	} {
		if got := sameOrSubdomain(c.host, c.origin); got != c.want {
			t.Errorf("sameOrSubdomain(%q, %q) = %v", c.host, c.origin, got)
		}
	}
}
