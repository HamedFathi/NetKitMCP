// Package httpx is the shared HTTP client factory. Every HTTP-based tool
// (http_*, GraphQL, SOAP, SSE, JSON/XML-RPC, uploads, fetch_web, tus, ...)
// builds its client here so the SSRF guard, TLS options, proxy, redirect
// policy, auth and limits apply uniformly.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Factory builds per-call HTTP clients.
type Factory struct {
	Cfg   *config.Config
	Guard *netguard.Guard
	Files *fileio.Policy
	Auth  *auth.Manager

	// TransportHook, when set, wraps the protocol transport below the guard
	// (the guard still checks every request and redirect). It exists so
	// tests can serve synthetic "public" hosts in-process; production code
	// leaves it nil.
	TransportHook func(http.RoundTripper) http.RoundTripper
}

// Client is a per-call HTTP client plus metadata collected while it runs.
type Client struct {
	*http.Client
	Dialer           *netguard.Dialer
	Options          types.HTTPOptions
	Timeout          time.Duration
	MaxResponseBytes int64
	Insecure         bool
	Redirects        []string
	TLSConfig        *tls.Config
	// HTTP3 is true when the client speaks HTTP/3 (QUIC).
	HTTP3   bool
	factory *Factory
	closeFn func()
}

// Close releases transport resources (idle connections, QUIC sockets).
func (c *Client) Close() {
	if c.closeFn != nil {
		c.closeFn()
	}
}

// AuthEnv returns the auth environment backed by this factory.
func (f *Factory) AuthEnv(allowPrivate bool) auth.Env {
	return auth.Env{
		Files: f.Files,
		TokenClient: func() *http.Client {
			c, err := f.New(types.HTTPOptions{NetOptions: types.NetOptions{AllowPrivate: allowPrivate}}, nil)
			if err != nil {
				return &http.Client{Transport: errTransport{err}}
			}
			return c.Client
		},
	}
}

type errTransport struct{ err error }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// New builds a client for one call. a may be nil (no auth).
func (f *Factory) New(opts types.HTTPOptions, a *auth.Config) (*Client, error) {
	if a != nil {
		auth.ApplyTLS(a, &opts.TLSOptions)
	}
	timeout := f.Cfg.Timeout(opts.TimeoutSeconds)
	d := f.Guard.Dialer(opts.AllowPrivate, timeout)
	c := &Client{
		Dialer:           d,
		Options:          opts,
		Timeout:          timeout,
		MaxResponseBytes: f.Cfg.ResponseBytes(opts.MaxResponseBytes),
		Insecure:         opts.InsecureSkipVerify,
		factory:          f,
	}
	tlsCfg, err := tlsx.Config(f.Files, opts.TLSOptions, "", nil)
	if err != nil {
		return nil, err
	}
	c.TLSConfig = tlsCfg

	var base http.RoundTripper
	switch v := strings.TrimPrefix(strings.ToUpper(opts.HTTPVersion), "HTTP/"); v {
	case "3", "3.0":
		if opts.Proxy != "" {
			return nil, errors.New("http_version 3 cannot be used with a proxy")
		}
		h3 := &http3.Transport{
			TLSClientConfig: tlsCfg.Clone(),
			Dial: func(ctx context.Context, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return dialQUIC(ctx, d, addr, tc, qc)
			},
		}
		base = h3
		c.HTTP3 = true
		c.closeFn = func() { h3.Close() }
	case "", "1.1", "1", "1.0", "2", "2.0":
		tr := &http.Transport{
			DialContext:           d.DialContext,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ExpectContinueTimeout: time.Second,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		}
		switch v {
		case "1.1", "1", "1.0":
			p := new(http.Protocols)
			p.SetHTTP1(true)
			tr.Protocols = p
			tr.ForceAttemptHTTP2 = false
		case "2", "2.0":
			p := new(http.Protocols)
			p.SetHTTP2(true)
			p.SetUnencryptedHTTP2(true)
			tr.Protocols = p
		}
		if opts.Proxy != "" {
			pu, err := url.Parse(opts.Proxy)
			if err != nil || pu.Host == "" {
				return nil, fmt.Errorf("invalid proxy URL %q", opts.Proxy)
			}
			switch pu.Scheme {
			case "http", "https", "socks5", "socks5h":
			default:
				return nil, fmt.Errorf("unsupported proxy scheme %q", pu.Scheme)
			}
			tr.Proxy = http.ProxyURL(pu)
		}
		base = tr
		c.closeFn = tr.CloseIdleConnections
	default:
		return nil, fmt.Errorf("unsupported http_version %q (use 1.1, 2 or 3)", opts.HTTPVersion)
	}

	if f.TransportHook != nil {
		base = f.TransportHook(base)
	}
	base = &guardTransport{base: base, d: d, proxied: opts.Proxy != "", h3: c.HTTP3}
	if a != nil {
		authed, err := f.Auth.Transport(base, a, f.AuthEnv(opts.AllowPrivate))
		if err != nil {
			return nil, err
		}
		base = &originAuth{authed: authed, plain: base}
	}

	follow := types.BoolDefault(opts.FollowRedirects, true)
	maxRedirects := f.Cfg.Redirects(opts.MaxRedirects)
	c.Client = &http.Client{
		Transport: base,
		Timeout:   0, // per-request contexts carry deadlines; streaming tools need long bodies
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !follow {
				return http.ErrUseLastResponse
			}
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if err := d.CheckHost(req.URL.Hostname()); err != nil {
				return err
			}
			c.Redirects = append(c.Redirects, req.URL.String())
			return nil
		},
	}
	return c, nil
}

// guardTransport checks the target host of every request (including
// redirects and proxied requests) against host lists; direct connections
// are additionally IP-checked in the dialer.
type guardTransport struct {
	base    http.RoundTripper
	d       *netguard.Dialer
	proxied bool
	h3      bool
}

func (g *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "https":
	case "http":
		if g.h3 {
			closeBody(req)
			return nil, errors.New("http_version 3 requires an https:// URL (QUIC is always encrypted)")
		}
	default:
		closeBody(req)
		return nil, fmt.Errorf("unsupported URL scheme %q (use http or https)", req.URL.Scheme)
	}
	host := req.URL.Hostname()
	if err := g.d.CheckHost(host); err != nil {
		closeBody(req)
		return nil, err
	}
	if g.proxied && !g.d.AllowsPrivate() {
		// Best effort: the proxy resolves the name, so check what we resolve.
		ips, err := net.DefaultResolver.LookupNetIP(req.Context(), "ip", host)
		if err == nil {
			for _, ip := range ips {
				if err := g.d.CheckIP(ip); err != nil {
					closeBody(req)
					return nil, err
				}
			}
		}
	}
	return g.base.RoundTrip(req)
}

// originAuth applies the call's auth only to the host the request was made
// for. Redirects to another host go out without credentials, matching what
// net/http does for an explicit Authorization header (same host or a
// subdomain of it keeps them).
type originAuth struct {
	authed, plain http.RoundTripper
}

func (o *originAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	first := req
	for first.Response != nil && first.Response.Request != nil {
		first = first.Response.Request
	}
	if first != req && !sameOrSubdomain(req.URL.Hostname(), first.URL.Hostname()) {
		return o.plain.RoundTrip(req)
	}
	return o.authed.RoundTrip(req)
}

func sameOrSubdomain(host, origin string) bool {
	host, origin = strings.ToLower(host), strings.ToLower(origin)
	if host == origin {
		return true
	}
	// IP literals never match as subdomains.
	if net.ParseIP(origin) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+origin)
}

// dialQUIC opens a QUIC connection to a guard-checked address, reporting
// connection and handshake timing to any httptrace in ctx.
func dialQUIC(ctx context.Context, d *netguard.Dialer, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
	trace := httptrace.ContextClientTrace(ctx)
	host, _, _ := net.SplitHostPort(addr)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(httptrace.DNSStartInfo{Host: host})
	}
	ap, err := d.ResolveChecked(ctx, addr)
	if trace != nil && trace.DNSDone != nil {
		trace.DNSDone(httptrace.DNSDoneInfo{Err: err})
	}
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if ap.Addr().Is6() {
		network = "udp6"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart("udp", ap.String())
	}
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(ap), tc, qc)
	var state tls.ConnectionState
	if conn != nil {
		state = conn.ConnectionState().TLS
	}
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(state, err)
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone("udp", ap.String(), err)
	}
	if err != nil {
		udp.Close()
		return nil, err
	}
	go func() { <-conn.Context().Done(); udp.Close() }()
	return conn, nil
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// Context returns a context bounded by the client's timeout.
func (c *Client) Context(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.Timeout)
}

// UserAgent returns the configured default user agent.
func (c *Client) UserAgent() string { return c.factory.Cfg.UserAgent }
