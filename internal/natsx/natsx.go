// Package natsx connects to core NATS with github.com/nats-io/nats.go. All
// TCP connections go through a caller supplied dialer (the SSRF guard), and
// reconnects are disabled so a one-shot call never wanders to servers the
// cluster advertises.
package natsx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Config describes a connection.
type Config struct {
	// Servers are nats://, tls://, ws:// or wss:// URLs.
	Servers []string
	Dialer  nats.CustomDialer
	// TLS, when non-nil, requires TLS (nats.Secure).
	TLS *tls.Config
	// TLSFirst performs the TLS handshake before the NATS INFO exchange.
	TLSFirst bool

	User, Password string
	Token          string
	// NKeySeed is an NKey user seed ("SU...").
	NKeySeed string
	// JWT + JWTSeed come from a .creds file (see ParseCreds).
	JWT, JWTSeed string

	Name    string
	Timeout time.Duration
	// OnAsyncError receives slow-consumer and permission errors.
	OnAsyncError func(error)
	// OnDisconnect is called when the connection drops.
	OnDisconnect func(error)
}

// NormalizeServers splits a comma-separated server list and adds the
// nats:// scheme and the default port to bare host[:port] entries.
func NormalizeServers(raw string) ([]string, error) {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "://") {
			s = "nats://" + s
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("invalid server URL %q: %w", s, err)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		switch u.Scheme {
		case "nats", "tls":
			if u.Port() == "" {
				u.Host = net.JoinHostPort(u.Hostname(), "4222")
			}
		case "ws", "wss":
		default:
			return nil, fmt.Errorf("unsupported NATS URL scheme %q (use nats, tls, ws or wss)", u.Scheme)
		}
		if u.Hostname() == "" {
			return nil, fmt.Errorf("server URL %q has no host", s)
		}
		out = append(out, u.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("url is required (e.g. nats://host:4222)")
	}
	return out, nil
}

// ParseCreds extracts the user JWT and NKey seed from .creds file contents.
func ParseCreds(contents []byte) (jwt, seed string, err error) {
	jwt, err = nkeys.ParseDecoratedJWT(contents)
	if err != nil {
		return "", "", fmt.Errorf("creds: %w", err)
	}
	kp, err := nkeys.ParseDecoratedUserNKey(contents)
	if err != nil {
		return "", "", fmt.Errorf("creds: %w", err)
	}
	s, err := kp.Seed()
	if err != nil {
		return "", "", fmt.Errorf("creds: %w", err)
	}
	return jwt, string(s), nil
}

// Connect opens a NATS connection.
func Connect(cfg Config) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.NoReconnect(),
		nats.DontRandomize(),
		nats.Name(cfg.Name),
	}
	if cfg.Dialer != nil {
		opts = append(opts, nats.SetCustomDialer(cfg.Dialer))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, nats.Timeout(cfg.Timeout))
	}
	if cfg.TLS != nil {
		opts = append(opts, nats.Secure(cfg.TLS))
		if cfg.TLSFirst {
			opts = append(opts, nats.TLSHandshakeFirst())
		}
	}
	if cfg.User != "" || cfg.Password != "" {
		opts = append(opts, nats.UserInfo(cfg.User, cfg.Password))
	}
	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	}
	switch {
	case cfg.JWT != "":
		opts = append(opts, nats.UserJWTAndSeed(cfg.JWT, cfg.JWTSeed))
	case cfg.NKeySeed != "":
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(cfg.NKeySeed)))
		if err != nil {
			return nil, fmt.Errorf("nkey_seed: %w", err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("nkey_seed: %w", err)
		}
		opts = append(opts, nats.Nkey(pub, kp.Sign))
	}
	if cfg.OnAsyncError != nil {
		opts = append(opts, nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { cfg.OnAsyncError(err) }))
	}
	if cfg.OnDisconnect != nil {
		opts = append(opts, nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { cfg.OnDisconnect(err) }))
	}
	nc, err := nats.Connect(strings.Join(cfg.Servers, ","), opts...)
	if err != nil {
		if errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) {
			return nil, fmt.Errorf("NATS connect: authentication failed, the server rejected the credentials (check username/password, token, nkey_seed or creds): %w", err)
		}
		return nil, fmt.Errorf("NATS connect: %w", err)
	}
	return nc, nil
}

// Headers converts a header map into nats.Header (nil when empty).
func Headers(m map[string]string) nats.Header {
	if len(m) == 0 {
		return nil
	}
	h := nats.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

// FlattenHeaders renders nats.Header for results; repeated values are
// joined with ", ".
func FlattenHeaders(h nats.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = strings.Join(h[k], ", ")
	}
	return out
}

// ValidateSubject checks a publish subject (no wildcards, no spaces).
func ValidateSubject(s string, wildcards bool) error {
	if s == "" {
		return fmt.Errorf("subject is required")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("subject %q must not contain whitespace", s)
	}
	for i, tok := range strings.Split(s, ".") {
		if tok == "" {
			return fmt.Errorf("subject %q has an empty token", s)
		}
		if tok == "*" || tok == ">" || strings.ContainsAny(tok, "*>") {
			if !wildcards {
				return fmt.Errorf("subject %q contains a wildcard; wildcards are only valid when subscribing", s)
			}
			if tok != "*" && tok != ">" {
				return fmt.Errorf("subject %q: wildcards must occupy an entire token", s)
			}
			if tok == ">" && i != len(strings.Split(s, "."))-1 {
				return fmt.Errorf("subject %q: '>' must be the last token", s)
			}
		}
	}
	return nil
}
