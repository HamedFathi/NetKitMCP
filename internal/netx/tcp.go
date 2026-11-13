package netx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// TCPRequest describes one raw TCP exchange: connect, optionally wrap in
// TLS, send, then read until a stop condition fires.
type TCPRequest struct {
	Addr      string      // host:port
	Dial      DialFunc    // guarded dialer (required)
	TLS       *tls.Config // nil = plaintext
	Send      io.Reader   // data to send (nil = nothing)
	HalfClose bool        // close the write side after sending
	NoRead    bool        // do not read at all

	Delimiter []byte        // stop once this sequence is received (inclusive)
	ReadBytes int64         // stop once this many bytes are received
	MaxBytes  int64         // bytes retained (required, > 0)
	Idle      time.Duration // stop after this long without data (0 = none)
}

// TCPResult is the outcome of a TCP exchange.
type TCPResult struct {
	Data          []byte
	BytesSent     int64
	BytesReceived int64
	EndedBy       string
	Truncated     bool
	SendError     string
	ReadError     string
	ConnectMS     float64
	TLSMS         float64
	FirstByteMS   float64 // -1 when nothing was received
	TotalMS       float64
	TLS           *tls.ConnectionState
	LocalAddr     string
	RemoteAddr    string
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// TCPExchange runs the exchange. Connection and TLS handshake failures are
// returned as errors; failures after the connection is up are reported in
// the result (EndedBy "error") together with whatever was received.
func TCPExchange(ctx context.Context, r TCPRequest) (*TCPResult, error) {
	if r.Dial == nil {
		return nil, errors.New("netx: no dialer")
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = 1 << 20
	}
	start := time.Now()
	raw, err := r.Dial(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, err
	}
	res := &TCPResult{ConnectMS: MS(time.Since(start)), FirstByteMS: -1,
		LocalAddr: raw.LocalAddr().String(), RemoteAddr: raw.RemoteAddr().String()}
	var conn net.Conn = raw
	defer func() { conn.Close() }()
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()) })
	defer stop()

	if r.TLS != nil {
		t0 := time.Now()
		tc := tls.Client(raw, r.TLS)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake with %s: %w", r.Addr, err)
		}
		res.TLSMS = MS(time.Since(t0))
		cs := tc.ConnectionState()
		res.TLS = &cs
		conn = tc
	}

	var sent atomic.Int64
	var writeFinished atomic.Bool
	writeDone := make(chan error, 1)
	go func() {
		var err error
		if r.Send != nil {
			_, err = io.Copy(countingWriter{conn, &sent}, r.Send)
		}
		if err == nil && r.HalfClose {
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		writeFinished.Store(true)
		if r.Idle > 0 && ctx.Err() == nil {
			conn.SetReadDeadline(time.Now().Add(r.Idle))
		}
		writeDone <- err
	}()

	finishWrite := func(force bool) {
		var err error
		if force {
			select {
			case err = <-writeDone:
			case <-time.After(50 * time.Millisecond):
				conn.Close()
				<-writeDone
				err = errors.New("send aborted: reading finished before all data was sent")
			}
		} else {
			err = <-writeDone
		}
		if err != nil && res.SendError == "" {
			res.SendError = err.Error()
		}
		res.BytesSent = sent.Load()
	}

	if r.NoRead {
		finishWrite(false)
		res.EndedBy = EndedNoRead
		if res.SendError != "" {
			res.EndedBy = EndedError
		}
		res.TotalMS = MS(time.Since(start))
		return res, nil
	}

	buf := make([]byte, 32<<10)
	var data []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if res.FirstByteMS < 0 {
				res.FirstByteMS = MS(time.Since(start))
			}
			res.BytesReceived += int64(n)
			prev := len(data)
			chunk := buf[:n]
			if room := r.MaxBytes - int64(len(data)); int64(n) > room {
				chunk = chunk[:room]
				res.Truncated = true
			}
			data = append(data, chunk...)
			if len(r.Delimiter) > 0 {
				from := max(prev-len(r.Delimiter)+1, 0)
				if i := bytes.Index(data[from:], r.Delimiter); i >= 0 {
					data = data[:from+i+len(r.Delimiter)]
					res.Truncated = false
					res.EndedBy = EndedDelimiter
					break
				}
			}
			if r.ReadBytes > 0 && int64(len(data)) >= r.ReadBytes {
				data = data[:r.ReadBytes]
				res.Truncated = false
				res.EndedBy = EndedLength
				break
			}
			if res.Truncated {
				res.EndedBy = EndedMaxBytes
				break
			}
			if r.Idle > 0 && writeFinished.Load() && ctx.Err() == nil {
				conn.SetReadDeadline(time.Now().Add(r.Idle))
			}
		}
		if err != nil {
			var ne net.Error
			switch {
			case errors.Is(err, io.EOF):
				res.EndedBy = EndedPeerClosed
			case ctx.Err() != nil:
				res.EndedBy = EndedTimeout
			case errors.As(err, &ne) && ne.Timeout():
				res.EndedBy = EndedIdle
			default:
				res.EndedBy = EndedError
				res.ReadError = err.Error()
			}
			break
		}
	}
	finishWrite(true)
	res.Data = data
	res.TotalMS = MS(time.Since(start))
	return res, nil
}
