package fileio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome points os.UserHomeDir at dir for the duration of the test.
func withHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // Windows
}

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	cases := map[string]string{
		"~":           home,
		"~/netkit/in": filepath.Join(home, "netkit", "in"),
		"/abs/~/x":    "/abs/~/x",
		"rel/~":       "rel/~",
		"~other/x":    "~other/x",
		"~notaslash":  "~notaslash",
		"":            "",
	}
	if os.PathSeparator == '\\' {
		cases[`~\netkit\out`] = filepath.Join(home, "netkit", "out")
	}
	for in, want := range cases {
		got, err := expandHome(in)
		if err != nil {
			t.Fatalf("expandHome(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

// A "~" that reaches the server unexpanded (MCP clients launch servers
// without a shell) must still resolve to the home directory.
func TestPolicyExpandsTilde(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	in := filepath.Join(home, "netkit", "in")
	out := filepath.Join(home, "netkit", "out")
	for _, d := range []string{in, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(in, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy([]string{"~/netkit/in"}, []string{"~/netkit/out"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ResolveRead(filepath.Join(in, "a.txt")); err != nil {
		t.Fatal("read under expanded dir:", err)
	}
	if _, err := p.ResolveWrite(filepath.Join(out, "b.txt"), false); err != nil {
		t.Fatal("write under expanded dir:", err)
	}
	wd := p.WriteDirs()
	if len(wd) != 1 || wd[0] != mustReal(t, out) {
		t.Fatalf("WriteDirs = %v, want [%s]", wd, mustReal(t, out))
	}
}

func TestPolicyMissingDirMessage(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	_, err := NewPolicy([]string{"~/netkit/missing"}, nil)
	if err == nil {
		t.Fatal("expected an error for a missing directory")
	}
	msg := err.Error()
	want := filepath.Join(home, "netkit", "missing")
	if !strings.Contains(msg, "does not exist; create it first") || !strings.Contains(msg, want) {
		t.Fatalf("error %q should name %s and say to create it", msg, want)
	}
	if !strings.Contains(msg, `allow-read-dir "~/netkit/missing"`) {
		t.Fatalf("error %q should quote the configured value", msg)
	}
}
