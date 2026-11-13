package fileio

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/fileio/linktest"
)

// TestDirLinks covers directory links (junctions on Windows, which
// filepath.EvalSymlinks does not resolve).
func TestDirLinks(t *testing.T) {
	base := t.TempDir()
	in := filepath.Join(base, "in")
	out := filepath.Join(base, "out")
	secret := filepath.Join(base, "secret")
	data := filepath.Join(out, "data")
	for _, d := range []string{in, out, secret, data} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(secret, "s.txt"), []byte("nope"), 0o644)
	os.WriteFile(filepath.Join(data, "ok.txt"), []byte("ok"), 0o644)
	for link, target := range map[string]string{
		filepath.Join(in, "esc"):    secret,
		filepath.Join(out, "esc"):   secret,
		filepath.Join(out, "alias"): data,
		filepath.Join(in, "toout"):  data,
	} {
		if err := linktest.DirLink(target, link); err != nil {
			t.Skipf("directory links unavailable: %v", err)
		}
	}
	// The allowed dir itself may be reached through a link.
	inLink := filepath.Join(base, "in-link")
	if err := linktest.DirLink(in, inLink); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy([]string{inLink}, []string{out})
	if err != nil {
		t.Fatal(err)
	}
	denied := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want ErrDenied, got %v", what, err)
		}
	}
	_, err = p.ResolveRead(filepath.Join(in, "esc", "s.txt"))
	denied("read via in/esc", err)
	_, err = p.ResolveRead("esc/s.txt")
	denied("relative read via esc", err)
	_, err = p.ResolveRead(filepath.Join(out, "esc", "s.txt"))
	denied("read via out/esc", err)
	_, err = p.ResolveWrite(filepath.Join(out, "esc", "new.txt"), false)
	denied("write via out/esc", err)
	_, err = p.ResolveWrite(filepath.Join(out, "esc", "s.txt"), true)
	denied("overwrite via out/esc", err)
	_, err = p.ResolveDir(filepath.Join(out, "esc"))
	denied("dir via out/esc", err)

	if r, err := p.ResolveRead(filepath.Join(out, "alias", "ok.txt")); err != nil || r != filepath.Join(mustReal(t, data), "ok.txt") {
		t.Errorf("inside link read: %q %v", r, err)
	}
	if _, err := p.ResolveRead(filepath.Join(in, "toout", "ok.txt")); err != nil {
		t.Errorf("link from read dir into write dir: %v", err)
	}
	if r, err := p.ResolveWrite(filepath.Join(out, "alias", "new.txt"), false); err != nil || r != filepath.Join(mustReal(t, data), "new.txt") {
		t.Errorf("inside link write: %q %v", r, err)
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestOutsidePathsDoNotLeakExistence: paths that are lexically outside the
// allowed directories are refused before the filesystem is consulted, so
// existing and missing files produce the same error.
func TestOutsidePathsDoNotLeakExistence(t *testing.T) {
	base := t.TempDir()
	in := filepath.Join(base, "in")
	out := filepath.Join(base, "out")
	other := filepath.Join(base, "other")
	for _, d := range []string{in, out, other} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(other, "exists.txt"), []byte("x"), 0o644)
	p, err := NewPolicy([]string{in}, []string{out})
	if err != nil {
		t.Fatal(err)
	}
	strip := func(err error, path string) string {
		if err == nil {
			return "<nil>"
		}
		return strings.ReplaceAll(err.Error(), strconv.Quote(path), "PATH")
	}
	for _, name := range []string{"exists.txt", "missing.txt"} {
		for _, path := range []string{filepath.Join(other, name), filepath.Join("..", "other", name)} {
			_, rerr := p.ResolveRead(path)
			_, werr := p.ResolveWrite(path, false)
			_, derr := p.ResolveDir(path)
			for what, err := range map[string]error{"read": rerr, "write": werr, "dir": derr} {
				if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "outside the allowed") {
					t.Errorf("%s %s: %v", what, path, err)
				}
			}
		}
	}
	_, e1 := p.ResolveRead(filepath.Join(other, "exists.txt"))
	_, e2 := p.ResolveRead(filepath.Join(other, "missing.txt"))
	if strip(e1, filepath.Join(other, "exists.txt")) != strip(e2, filepath.Join(other, "missing.txt")) {
		t.Errorf("errors differ: %v / %v", e1, e2)
	}
}
