// Package transfer holds helpers shared by the file-transfer protocol
// packages (tus, S3 multipart, SFTP, FTP): position-aware hashing for
// resumable uploads, idle-timeout connections and retry backoff.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net"
	"sync"
	"time"
)

// SeqHasher computes the SHA-256 of a file whose bytes are observed out of
// order or more than once (retries, resumed uploads). Bytes are hashed in
// file order exactly once; gaps are filled by reading the file itself.
type SeqHasher struct {
	mu  sync.Mutex
	src io.ReaderAt
	h   hash.Hash
	n   int64
	err error
}

// NewSeqHasher returns a hasher that reads gaps from src.
func NewSeqHasher(src io.ReaderAt) *SeqHasher {
	return &SeqHasher{src: src, h: sha256.New()}
}

// Feed records that b (located at file offset pos) was sent.
func (s *SeqHasher) Feed(pos int64, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	if pos > s.n {
		s.catchUpLocked(pos)
		if s.err != nil {
			return
		}
	}
	end := pos + int64(len(b))
	if end <= s.n {
		return
	}
	s.h.Write(b[s.n-pos:])
	s.n = end
}

func (s *SeqHasher) catchUpLocked(upto int64) {
	if upto <= s.n {
		return
	}
	_, err := io.Copy(s.h, io.NewSectionReader(s.src, s.n, upto-s.n))
	if err != nil {
		s.err = err
		return
	}
	s.n = upto
}

// Finish hashes any remaining bytes up to size and returns the hex digest.
func (s *SeqHasher) Finish(size int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.catchUpLocked(size)
	if s.err != nil {
		return "", s.err
	}
	return hex.EncodeToString(s.h.Sum(nil)), nil
}

// ObservedReader reads a section of a file, reporting each chunk read with
// its file offset (for hashing and progress).
type ObservedReader struct {
	R       io.Reader
	Pos     int64
	Observe func(pos int64, b []byte)
}

func (o *ObservedReader) Read(p []byte) (int, error) {
	n, err := o.R.Read(p)
	if n > 0 {
		if o.Observe != nil {
			o.Observe(o.Pos, p[:n])
		}
		o.Pos += int64(n)
	}
	return n, err
}

// IdleConn extends the connection deadline on every read and write, so a
// transfer of any length ends only when the peer stalls for Idle.
type IdleConn struct {
	net.Conn
	Idle time.Duration
}

// NewIdleConn wraps c; idle <= 0 disables the deadline.
func NewIdleConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	return &IdleConn{Conn: c, Idle: idle}
}

func (c *IdleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.Idle))
	return c.Conn.Read(p)
}

func (c *IdleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.Idle))
	return c.Conn.Write(p)
}

// Closers closes registered resources when a context ends.
type Closers struct {
	mu     sync.Mutex
	items  []io.Closer
	closed bool
	stop   chan struct{}
}

// CloseOnDone returns a Closers that closes everything added to it when
// ctx is done. Call Stop when the operation finishes normally.
func CloseOnDone(ctx context.Context) *Closers {
	c := &Closers{stop: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			c.CloseAll()
		case <-c.stop:
		}
	}()
	return c
}

// Add registers a closer (closed immediately if already cancelled).
func (c *Closers) Add(x io.Closer) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		x.Close()
		return
	}
	c.items = append(c.items, x)
	c.mu.Unlock()
}

// CloseAll closes every registered resource.
func (c *Closers) CloseAll() {
	c.mu.Lock()
	items := c.items
	c.items = nil
	c.closed = true
	c.mu.Unlock()
	for _, x := range items {
		x.Close()
	}
}

// Stop ends the watcher without closing anything.
func (c *Closers) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

// Backoff sleeps before retry attempt n (1-based): base * 2^(n-1), capped
// at 15s. It returns the context error if ctx ends first.
func Backoff(ctx context.Context, base time.Duration, attempt int) error {
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	d := base
	for i := 1; i < attempt && d < 15*time.Second; i++ {
		d *= 2
	}
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// CountingWriter counts bytes and reports progress.
type CountingWriter struct {
	W        io.Writer
	N        int64
	Base     int64
	Total    int64
	Progress func(done, total int64)
}

func (w *CountingWriter) Write(p []byte) (int, error) {
	n, err := w.W.Write(p)
	w.N += int64(n)
	if n > 0 && w.Progress != nil {
		w.Progress(w.Base+w.N, w.Total)
	}
	return n, err
}
