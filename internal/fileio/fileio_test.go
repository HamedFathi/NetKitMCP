package fileio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicy(t *testing.T) {
	base := t.TempDir()
	in := filepath.Join(base, "in")
	out := filepath.Join(base, "out")
	secret := filepath.Join(base, "secret")
	for _, d := range []string{in, out, secret} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(in, "a.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(secret, "s.txt"), []byte("nope"), 0o644)
	p, err := NewPolicy([]string{in}, []string{out})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ResolveRead(filepath.Join(in, "a.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ResolveRead("a.txt"); err != nil {
		t.Fatal("relative path:", err)
	}
	if _, err := p.ResolveRead(filepath.Join(in, "..", "secret", "s.txt")); !errors.Is(err, ErrDenied) {
		t.Fatalf("traversal not denied: %v", err)
	}
	if _, err := p.ResolveRead("../secret/s.txt"); !errors.Is(err, ErrDenied) {
		t.Fatalf("relative traversal not denied: %v", err)
	}
	if err := os.Symlink(filepath.Join(secret, "s.txt"), filepath.Join(in, "link.txt")); err == nil {
		if _, err := p.ResolveRead(filepath.Join(in, "link.txt")); !errors.Is(err, ErrDenied) {
			t.Fatalf("symlink escape not denied: %v", err)
		}
	}
	if _, err := p.ResolveWrite(filepath.Join(in, "x.txt"), false); !errors.Is(err, ErrDenied) {
		t.Fatalf("write to read-only dir not denied: %v", err)
	}
	w, err := p.CreateWrite(filepath.Join(out, "dl.bin"), false, 10)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("12345"))
	info, err := w.Commit()
	if err != nil || info.SizeBytes != 5 || info.SHA256 == "" {
		t.Fatalf("commit: %v %+v", err, info)
	}
	if _, err := p.CreateWrite(filepath.Join(out, "dl.bin"), false, 0); !errors.Is(err, ErrDenied) {
		t.Fatalf("overwrite not denied: %v", err)
	}
	w, _ = p.CreateWrite(filepath.Join(out, "big.bin"), false, 3)
	if _, err := w.Write([]byte("12345")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	w.Abort()
	if _, err := os.Stat(filepath.Join(out, "big.bin")); !os.IsNotExist(err) {
		t.Fatal("aborted file exists")
	}
}
