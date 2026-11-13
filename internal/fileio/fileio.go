// Package fileio confines file access to configured directories and provides
// streaming, hashing helpers. Every file a tool reads or writes goes through
// a Policy.
package fileio

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ErrDenied is wrapped by every policy violation.
var ErrDenied = errors.New("file access denied by netkit policy")

// Policy restricts reads and writes to allowed directories.
type Policy struct {
	readDirs  []string
	writeDirs []string
	// readLex and writeLex hold both the canonical and the configured
	// (absolute, cleaned) spelling of each directory. For a requested path
	// that is not lexically inside one of them, every resolution failure is
	// reported as "outside the allowed directories", so errors never reveal
	// what exists outside them. (Such a path can still be allowed when it
	// resolves inside, e.g. via an 8.3 short name or a link to an allowed dir.)
	readLex  []string
	writeLex []string
}

// NewPolicy builds a policy. A leading "~" is expanded to the user's home
// directory, then directories are resolved to absolute, symlink-free paths.
// Write directories are implicitly readable.
func NewPolicy(readDirs, writeDirs []string) (*Policy, error) {
	p := &Policy{}
	for _, d := range readDirs {
		e, r, err := configuredDir(d)
		if err != nil {
			return nil, fmt.Errorf("allow-read-dir %q: %w", d, err)
		}
		p.readDirs = append(p.readDirs, r)
		p.readLex = append(p.readLex, r, lexical(e))
	}
	for _, d := range writeDirs {
		e, r, err := configuredDir(d)
		if err != nil {
			return nil, fmt.Errorf("allow-write-dir %q: %w", d, err)
		}
		p.writeDirs = append(p.writeDirs, r)
		p.readDirs = append(p.readDirs, r)
		p.writeLex = append(p.writeLex, r, lexical(e))
		p.readLex = append(p.readLex, r, lexical(e))
	}
	return p, nil
}

// configuredDir expands and canonicalizes one configured directory,
// returning both the expanded spelling and the canonical path.
func configuredDir(d string) (expanded, canonical string, err error) {
	expanded, err = expandHome(d)
	if err != nil {
		return "", "", err
	}
	canonical, err = canonicalDir(expanded)
	return expanded, canonical, err
}

// expandHome replaces a leading "~" (alone, or followed by "/", or by "\" on
// Windows) with the user's home directory. MCP clients start servers without
// a shell, and PowerShell doesn't expand "~" in arguments to native programs,
// so a "~" in a client config would otherwise reach the server unexpanded.
// "~user" forms are left alone.
func expandHome(d string) (string, error) {
	if d != "~" && !strings.HasPrefix(d, "~/") && !(os.PathSeparator == '\\' && strings.HasPrefix(d, `~\`)) {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot expand ~: %w", err)
	}
	return filepath.Join(home, d[1:]), nil
}

func lexical(d string) string {
	if abs, err := filepath.Abs(d); err == nil {
		return abs
	}
	return filepath.Clean(d)
}

// ReadDirs returns the canonical readable directories.
func (p *Policy) ReadDirs() []string { return append([]string(nil), p.readDirs...) }

// WriteDirs returns the canonical writable directories.
func (p *Policy) WriteDirs() []string { return append([]string(nil), p.writeDirs...) }

func canonicalDir(d string) (string, error) {
	abs, err := filepath.Abs(d)
	if err != nil {
		return "", err
	}
	r, err := resolveLinks(abs)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("directory %s does not exist; create it first", abs)
	}
	if err != nil {
		return "", err
	}
	st, err := os.Stat(r)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("directory %s does not exist; create it first", abs)
	}
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	return filepath.Clean(r), nil
}

func within(dirs []string, p string) bool {
	for _, d := range dirs {
		rel, err := filepath.Rel(d, p)
		if err != nil {
			continue
		}
		if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)) {
			return true
		}
	}
	return false
}

// ResolveRead returns the canonical path of an existing regular file that may
// be read. Symlinks are resolved before the directory check.
func (p *Policy) ResolveRead(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty path", ErrDenied)
	}
	if len(p.readDirs) == 0 {
		return "", fmt.Errorf("%w: no readable directories configured (start the server with --allow-read-dir)", ErrDenied)
	}
	abs, err := p.absolute(path, p.readDirs)
	if err != nil {
		return "", err
	}
	outside := fmt.Errorf("%w: %q is outside the allowed read directories", ErrDenied, path)
	lexOK := within(p.readLex, abs)
	real, err := resolveLinks(abs)
	if err != nil {
		if !lexOK {
			return "", outside // never reveal what exists outside the allowed dirs
		}
		return "", fmt.Errorf("resolve %q: %w", path, err)
	}
	if !within(p.readDirs, real) {
		return "", outside
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %q is not a regular file", ErrDenied, path)
	}
	return real, nil
}

// ResolveWrite returns the canonical path that may be written. The parent
// directory must exist and be inside an allowed write directory. If the
// target exists, overwrite must be true and it must be a regular file.
func (p *Policy) ResolveWrite(path string, overwrite bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty path", ErrDenied)
	}
	if len(p.writeDirs) == 0 {
		return "", fmt.Errorf("%w: no writable directories configured (start the server with --allow-write-dir)", ErrDenied)
	}
	abs, err := p.absolute(path, p.writeDirs)
	if err != nil {
		return "", err
	}
	outside := fmt.Errorf("%w: %q is outside the allowed write directories", ErrDenied, path)
	lexOK := within(p.writeLex, abs)
	parent, err := resolveLinks(filepath.Dir(abs))
	if err != nil {
		if !lexOK {
			return "", outside
		}
		return "", fmt.Errorf("resolve parent of %q: %w", path, err)
	}
	target := filepath.Join(parent, filepath.Base(abs))
	if !within(p.writeDirs, target) {
		return "", outside
	}
	if st, err := os.Lstat(target); err == nil {
		if isLink(st) {
			real, err := resolveLinks(target)
			if err != nil {
				return "", err
			}
			target = real
			if !within(p.writeDirs, target) {
				return "", outside
			}
			st, err = os.Stat(target)
			if err != nil {
				return "", err
			}
		}
		if !overwrite {
			return "", fmt.Errorf("%w: %q already exists (set overwrite=true to replace it)", ErrDenied, path)
		}
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %q is not a regular file", ErrDenied, path)
		}
	}
	return target, nil
}

// ResolveDir returns a canonical directory path for listing or for a
// directory of .proto files; it must be inside a readable directory.
func (p *Policy) ResolveDir(path string) (string, error) {
	if len(p.readDirs) == 0 {
		return "", fmt.Errorf("%w: no readable directories configured (start the server with --allow-read-dir)", ErrDenied)
	}
	abs, err := p.absolute(path, p.readDirs)
	if err != nil {
		return "", err
	}
	outside := fmt.Errorf("%w: %q is outside the allowed read directories", ErrDenied, path)
	lexOK := within(p.readLex, abs)
	real, err := resolveLinks(abs)
	if err != nil {
		if !lexOK {
			return "", outside
		}
		return "", err
	}
	if !within(p.readDirs, real) {
		return "", outside
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%q is not a directory", path)
	}
	return real, nil
}

// absolute makes relative paths relative to the first allowed directory.
func (p *Policy) absolute(path string, dirs []string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("%w: relative path with no allowed directory", ErrDenied)
	}
	return filepath.Join(dirs[0], path), nil
}

// OpenRead opens an allowed file for streaming. maxBytes <= 0 means no limit.
func (p *Policy) OpenRead(path string, maxBytes int64) (*os.File, os.FileInfo, error) {
	real, err := p.ResolveRead(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %q is %d bytes, above the %d byte upload limit", ErrDenied, path, st.Size(), maxBytes)
	}
	return f, st, nil
}

// ReadSmall reads a small allowed file fully (certs, keys, WSDLs, protos).
func (p *Policy) ReadSmall(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	f, _, err := p.OpenRead(path, maxBytes)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// FileInfo is the file description reported in every transfer result.
type FileInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// HashFile computes size and SHA-256 of an allowed file without loading it
// into memory.
func (p *Policy) HashFile(path string) (FileInfo, error) {
	f, st, err := p.OpenRead(path, 0)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Name:        st.Name(),
		Path:        f.Name(),
		SizeBytes:   n,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		ContentType: DetectContentType(f.Name(), nil),
	}, nil
}

// DetectContentType guesses a content type from the extension, falling back
// to sniffing the first bytes (head may be nil).
func DetectContentType(name string, head []byte) string {
	if ct := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); ct != "" {
		return ct
	}
	if len(head) > 0 {
		return http.DetectContentType(head)
	}
	return "application/octet-stream"
}

// HashingReader wraps a reader, counting bytes and computing SHA-256.
type HashingReader struct {
	R io.Reader
	h hash.Hash
	n int64
}

// NewHashingReader wraps r.
func NewHashingReader(r io.Reader) *HashingReader { return &HashingReader{R: r, h: sha256.New()} }

func (h *HashingReader) Read(p []byte) (int, error) {
	n, err := h.R.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
	}
	return n, err
}

// N returns bytes read so far.
func (h *HashingReader) N() int64 { return h.n }

// SHA256 returns the hex digest of bytes read so far.
func (h *HashingReader) SHA256() string { return hex.EncodeToString(h.h.Sum(nil)) }

// AtomicWriter writes to a temp file in the target directory and renames it
// into place on Commit. Abort removes the temp file. Writes beyond maxBytes
// fail.
type AtomicWriter struct {
	f        *os.File
	target   string
	h        hash.Hash
	n        int64
	maxBytes int64
	done     bool
}

// CreateWrite resolves path against the policy and opens an AtomicWriter.
func (p *Policy) CreateWrite(path string, overwrite bool, maxBytes int64) (*AtomicWriter, error) {
	target, err := p.ResolveWrite(path, overwrite)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".netkit-*")
	if err != nil {
		return nil, err
	}
	return &AtomicWriter{f: f, target: target, h: sha256.New(), maxBytes: maxBytes}, nil
}

// ErrTooLarge is returned when a download exceeds its limit.
var ErrTooLarge = errors.New("size limit exceeded")

func (w *AtomicWriter) Write(p []byte) (int, error) {
	if w.maxBytes > 0 && w.n+int64(len(p)) > w.maxBytes {
		return 0, fmt.Errorf("%w: download exceeds %d bytes", ErrTooLarge, w.maxBytes)
	}
	n, err := w.f.Write(p)
	w.h.Write(p[:n])
	w.n += int64(n)
	return n, err
}

// N returns bytes written.
func (w *AtomicWriter) N() int64 { return w.n }

// Target returns the final path.
func (w *AtomicWriter) Target() string { return w.target }

// Commit syncs and renames the temp file into place.
func (w *AtomicWriter) Commit() (FileInfo, error) {
	if w.done {
		return FileInfo{}, errors.New("writer already finished")
	}
	w.done = true
	if err := w.f.Close(); err != nil {
		os.Remove(w.f.Name())
		return FileInfo{}, err
	}
	if err := os.Rename(w.f.Name(), w.target); err != nil {
		os.Remove(w.f.Name())
		return FileInfo{}, err
	}
	return FileInfo{
		Name:        filepath.Base(w.target),
		Path:        w.target,
		SizeBytes:   w.n,
		SHA256:      hex.EncodeToString(w.h.Sum(nil)),
		ContentType: DetectContentType(w.target, nil),
	}, nil
}

// Abort discards the temp file. Safe to call after Commit.
func (w *AtomicWriter) Abort() {
	if w.done {
		return
	}
	w.done = true
	w.f.Close()
	os.Remove(w.f.Name())
}
