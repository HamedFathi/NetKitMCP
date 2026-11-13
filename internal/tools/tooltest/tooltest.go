// Package tooltest runs tools end-to-end through an in-memory MCP client.
package tooltest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

// Harness is a connected in-memory MCP client plus temp directories.
type Harness struct {
	T        *testing.T
	Session  *mcp.ClientSession
	Deps     *tools.Deps
	ReadDir  string // allowed for reads
	WriteDir string // allowed for writes (and reads)
}

// Option customises the harness configuration.
type Option func(*config.Config)

// WithPrivateMode sets the private-network mode (tests default to "allow"
// because test servers listen on loopback).
func WithPrivateMode(m config.PrivateMode) Option {
	return func(c *config.Config) { c.PrivateMode = m }
}

// New starts a server with the given groups ("all" for everything).
func New(t *testing.T, groups string, opts ...Option) *Harness {
	t.Helper()
	base := t.TempDir()
	rd := filepath.Join(base, "in")
	wd := filepath.Join(base, "out")
	os.MkdirAll(rd, 0o755)
	os.MkdirAll(wd, 0o755)

	cfg := config.Default()
	cfg.PrivateMode = config.PrivateAllow
	cfg.AllowReadDirs = []string{rd}
	cfg.AllowWriteDirs = []string{wd}
	cfg.DefaultStreamTime = 5 * time.Second
	for _, o := range opts {
		o(cfg)
	}
	deps, err := tools.NewDeps(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g, err := tools.ParseGroups(groups)
	if err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "netkit-test", Version: "test"}, nil)
	tools.Register(srv, deps, g)

	ctx, cancel := context.WithCancel(context.Background())
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tooltest", Version: "test"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cs.Close()
		ss.Close()
		deps.Sessions.CloseAll()
		cancel()
	})
	// Resolve symlinks (e.g. macOS /var -> /private/var) so tests can compare.
	rdReal, _ := filepath.EvalSymlinks(rd)
	wdReal, _ := filepath.EvalSymlinks(wd)
	return &Harness{T: t, Session: cs, Deps: deps, ReadDir: rdReal, WriteDir: wdReal}
}

// Result is a decoded tool result.
type Result struct {
	IsError bool
	Text    string         // concatenated text content
	Data    map[string]any // structured content when it is an object
	Raw     json.RawMessage
}

// Call invokes a tool and decodes the result. It fails the test on
// protocol errors (not on tool errors).
func (h *Harness) Call(name string, args any) *Result {
	h.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := h.Session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.T.Fatalf("CallTool %s: %v", name, err)
	}
	out := &Result{IsError: res.IsError}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	out.Text = sb.String()
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		out.Raw = b
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			out.Data = m
		}
	}
	return out
}

// MustOK calls a tool and fails the test if it returned a tool error.
func (h *Harness) MustOK(name string, args any) *Result {
	h.T.Helper()
	r := h.Call(name, args)
	if r.IsError {
		h.T.Fatalf("%s returned error: %s", name, r.Text)
	}
	return r
}

// MustFail calls a tool and fails the test unless it returned a tool error
// containing substr.
func (h *Harness) MustFail(name string, args any, substr string) *Result {
	h.T.Helper()
	r := h.Call(name, args)
	if !r.IsError {
		h.T.Fatalf("%s: expected error containing %q, got success: %s", name, substr, r.Text)
	}
	if substr != "" && !strings.Contains(r.Text, substr) {
		h.T.Fatalf("%s: expected error containing %q, got: %s", name, substr, r.Text)
	}
	return r
}

// Decode unmarshals the structured result into v.
func (r *Result) Decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Raw, v); err != nil {
		t.Fatalf("decode result: %v\n%s", err, r.Raw)
	}
}

// WriteInput creates a file in the readable directory and returns its path.
func (h *Harness) WriteInput(name string, data []byte) string {
	h.T.Helper()
	p := filepath.Join(h.ReadDir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		h.T.Fatal(err)
	}
	return p
}

// ListTools returns the registered tool names.
func (h *Harness) ListTools() []string {
	h.T.Helper()
	res, err := h.Session.ListTools(context.Background(), nil)
	if err != nil {
		h.T.Fatal(err)
	}
	var names []string
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	return names
}
