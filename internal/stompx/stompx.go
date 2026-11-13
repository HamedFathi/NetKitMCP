// Package stompx connects github.com/go-stomp/stomp/v3 clients over
// connections dialed through the SSRF guard.
package stompx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-stomp/stomp/v3"

	"github.com/HamedFathi/NetKitMCP/internal/netguard"
)

// Target is a parsed STOMP address.
type Target struct {
	HostPort string
	Host     string
	TLS      bool
}

// ParseAddress accepts host:port or a URL with scheme stomp, tcp, stomp+ssl,
// stomps, ssl or tls. The default port is 61613 (61614 for TLS).
func ParseAddress(addr string, forceTLS bool) (Target, error) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return Target{}, fmt.Errorf("address is required (host:port or stomp://host:port)")
	}
	useTLS := forceTLS
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Target{}, fmt.Errorf("invalid address: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "stomp", "tcp":
		case "stomp+ssl", "stomps", "ssl", "tls", "stomp+tls":
			useTLS = true
		default:
			return Target{}, fmt.Errorf("unsupported scheme %q (use stomp://, stomp+ssl:// or host:port)", u.Scheme)
		}
		s = u.Host
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host = strings.Trim(s, "[]")
		port = "61613"
		if useTLS {
			port = "61614"
		}
	}
	if host == "" {
		return Target{}, fmt.Errorf("address %q has no host", addr)
	}
	return Target{HostPort: net.JoinHostPort(host, port), Host: host, TLS: useTLS}, nil
}

// Options configure a STOMP connection.
type Options struct {
	Login, Passcode string
	VHost           string // "host" header (default: the target host)
	HeartBeatSend   time.Duration
	HeartBeatRecv   time.Duration
	Versions        []string // "1.0", "1.1", "1.2"
	Headers         map[string]string
	Timeout         time.Duration
}

// Conn is a connected client plus the TLS state when TLS is used.
type Conn struct {
	*stomp.Conn
	TLS *tls.ConnectionState
	raw net.Conn
}

// Close disconnects gracefully (bounded) and closes the socket.
func (c *Conn) Close() {
	done := make(chan struct{})
	go func() {
		c.Conn.Disconnect()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	c.raw.Close()
}

// Dial connects through the guard, optionally wraps TLS and performs the
// STOMP CONNECT handshake.
func Dial(ctx context.Context, t Target, d *netguard.Dialer, tlsCfg *tls.Config, o Options) (*Conn, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", t.HostPort)
	if err != nil {
		return nil, err
	}
	var nc net.Conn = raw
	var state *tls.ConnectionState
	if t.TLS {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsCfg != nil {
			cfg = tlsCfg.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = t.Host
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		cs := tc.ConnectionState()
		state = &cs
		nc = tc
	}
	opts := []func(*stomp.Conn) error{
		stomp.ConnOpt.HeartBeat(o.HeartBeatSend, o.HeartBeatRecv),
		stomp.ConnOpt.MsgSendTimeout(timeout),
		stomp.ConnOpt.RcvReceiptTimeout(timeout),
		stomp.ConnOpt.DisconnectReceiptTimeout(2 * time.Second),
		stomp.ConnOpt.UnsubscribeReceiptTimeout(2 * time.Second),
		stomp.ConnOpt.SubscribeReceiptTimeout(timeout),
		stomp.ConnOpt.Logger(nopLogger{}),
	}
	host := o.VHost
	if host == "" {
		host = t.Host
	}
	opts = append(opts, stomp.ConnOpt.Host(host))
	if o.Login != "" || o.Passcode != "" {
		opts = append(opts, stomp.ConnOpt.Login(o.Login, o.Passcode))
	}
	if len(o.Versions) > 0 {
		var vs []stomp.Version
		for _, v := range o.Versions {
			switch strings.TrimSpace(v) {
			case "1.0":
				vs = append(vs, stomp.V10)
			case "1.1":
				vs = append(vs, stomp.V11)
			case "1.2":
				vs = append(vs, stomp.V12)
			default:
				raw.Close()
				return nil, fmt.Errorf("unsupported STOMP version %q (use 1.0, 1.1 or 1.2)", v)
			}
		}
		opts = append(opts, stomp.ConnOpt.AcceptVersion(vs...))
	}
	for k, v := range o.Headers {
		opts = append(opts, stomp.ConnOpt.Header(k, v))
	}
	sc, err := stomp.ConnectWithContext(dctx, nc, opts...)
	if err != nil {
		raw.Close()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("STOMP connect: no CONNECTED frame from %s before the deadline (is this a STOMP endpoint, and is tls set correctly? raise timeout_seconds): %w", t.HostPort, err)
		}
		return nil, fmt.Errorf("STOMP connect: %w", err)
	}
	return &Conn{Conn: sc, TLS: state, raw: raw}, nil
}

// AckMode parses auto|client|client-individual.
func AckMode(s string) (stomp.AckMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return stomp.AckAuto, nil
	case "client":
		return stomp.AckClient, nil
	case "client-individual", "client_individual":
		return stomp.AckClientIndividual, nil
	}
	return stomp.AckAuto, fmt.Errorf("ack must be auto, client or client-individual")
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...interface{})   {}
func (nopLogger) Debug(string)                    {}
func (nopLogger) Infof(string, ...interface{})    {}
func (nopLogger) Info(string)                     {}
func (nopLogger) Warningf(string, ...interface{}) {}
func (nopLogger) Warning(string)                  {}
func (nopLogger) Errorf(string, ...interface{})   {}
func (nopLogger) Error(string)                    {}
