package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Env carries what auth implementations need from the server.
type Env struct {
	Files *fileio.Policy
	// TokenClient returns a guarded HTTP client (no auth applied) used for
	// token endpoints and similar side requests.
	TokenClient func() *http.Client
	// CheckAddress, when set, validates host:port targets that auth code
	// dials outside the HTTP client (Kerberos KDCs) against the SSRF guard.
	CheckAddress func(hostport string) error
}

// Signer mutates an outgoing request (headers, query) to authenticate it.
// Implementations that need the body must use req.GetBody so the body can
// still be sent.
type Signer interface {
	Sign(ctx context.Context, req *http.Request) error
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(ctx context.Context, req *http.Request) error

// Sign implements Signer.
func (f SignerFunc) Sign(ctx context.Context, req *http.Request) error { return f(ctx, req) }

// Manager owns cross-call auth state (the OAuth2 token cache).
type Manager struct {
	mu     sync.Mutex
	tokens map[string]*cachedToken
}

// NewManager creates a Manager.
func NewManager() *Manager { return &Manager{tokens: map[string]*cachedToken{}} }

// challengeTypes need a round trip (server challenge) and therefore cannot be
// expressed as a static signer.
var challengeTypes = map[string]bool{"digest": true, "ntlm": true, "negotiate": true}

// connectionTypes are not HTTP auth at all; they are consumed by specific
// protocols (SOAP, SSH) or by TLS setup.
var connectionTypes = map[string]bool{"ws_security": true, "ssh_key": true, "ssh_password": true, "mtls": true}

// IsChallenge reports whether the type requires an HTTP challenge round trip.
func IsChallenge(c *Config) bool { return challengeTypes[c.Kind()] }

// Signer returns a static request signer for the config. It errors for
// challenge-based types (use Transport instead).
func (m *Manager) Signer(c *Config, env Env) (Signer, error) {
	switch k := c.Kind(); k {
	case "none", "mtls", "ws_security":
		return SignerFunc(func(context.Context, *http.Request) error { return nil }), nil
	case "basic":
		return SignerFunc(func(_ context.Context, r *http.Request) error {
			r.SetBasicAuth(c.Username, c.Password)
			return nil
		}), nil
	case "bearer":
		if c.Token == "" {
			return nil, fmt.Errorf("auth bearer: token is required")
		}
		prefix := c.Prefix
		if prefix == "" {
			prefix = "Bearer"
		}
		return SignerFunc(func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", strings.TrimSpace(prefix+" "+c.Token))
			return nil
		}), nil
	case "api_key":
		if c.Key == "" {
			return nil, fmt.Errorf("auth api_key: key is required")
		}
		return SignerFunc(func(_ context.Context, r *http.Request) error {
			switch strings.ToLower(c.In) {
			case "", "header":
				r.Header.Set(c.Key, c.Value)
			case "query":
				q := r.URL.Query()
				q.Set(c.Key, c.Value)
				r.URL.RawQuery = q.Encode()
			case "cookie":
				r.AddCookie(&http.Cookie{Name: c.Key, Value: c.Value})
			default:
				return fmt.Errorf("auth api_key: in must be header, query or cookie")
			}
			return nil
		}), nil
	case "custom_header":
		return SignerFunc(func(_ context.Context, r *http.Request) error {
			for k, v := range c.Headers {
				r.Header.Set(k, v)
			}
			return nil
		}), nil
	case "cookie":
		return SignerFunc(func(_ context.Context, r *http.Request) error {
			for k, v := range c.Cookies {
				r.AddCookie(&http.Cookie{Name: k, Value: v})
			}
			return nil
		}), nil
	case "ssh_key", "ssh_password":
		return nil, fmt.Errorf("auth %s applies only to SFTP", k)
	default:
		if challengeTypes[k] {
			return nil, fmt.Errorf("auth %s needs an HTTP challenge round trip and is only supported on HTTP-based tools", k)
		}
		return m.extSigner(c, env)
	}
}

// Transport wraps base with the authentication described by c.
func (m *Manager) Transport(base http.RoundTripper, c *Config, env Env) (http.RoundTripper, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	k := c.Kind()
	if k == "none" || k == "mtls" || k == "ws_security" {
		return base, nil
	}
	if challengeTypes[k] {
		return m.challengeTransport(base, c, env)
	}
	s, err := m.Signer(c, env)
	if err != nil {
		return nil, err
	}
	return &signingTransport{base: base, signer: s}, nil
}

type signingTransport struct {
	base   http.RoundTripper
	signer Signer
}

func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if req.Body != nil {
		r.Body = req.Body
	}
	if err := t.signer.Sign(req.Context(), r); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("auth: %w", err)
	}
	return t.base.RoundTrip(r)
}

// Headers computes the auth headers for a request without sending it, for
// protocols that carry HTTP-style credentials (WebSocket handshake, gRPC
// metadata, Socket.IO, MCP client). Query parameters added by the signer
// (api_key in=query, oauth1 in_query, jwt query_key) are returned in the
// rewritten URL.
func (m *Manager) Headers(ctx context.Context, c *Config, env Env, method, rawURL string) (http.Header, string, error) {
	if c.Kind() == "none" {
		return http.Header{}, rawURL, nil
	}
	s, err := m.Signer(c, env)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	if err := s.Sign(ctx, req); err != nil {
		return nil, "", err
	}
	return req.Header, req.URL.String(), nil
}

// ApplyTLS merges an mtls auth config into TLS options.
func ApplyTLS(c *Config, opts *types.TLSOptions) {
	if c.Kind() == "mtls" && c.MTLS != nil {
		if opts.ClientCert == "" {
			opts.ClientCert = c.MTLS.ClientCert
		}
		if opts.ClientKey == "" {
			opts.ClientKey = c.MTLS.ClientKey
		}
	}
}

// UserPass returns username/password for protocols with native credentials
// (MQTT, AMQP, NATS, Kafka SASL/PLAIN, FTP). For bearer it returns ("", token).
func UserPass(c *Config) (user, pass string, ok bool) {
	switch c.Kind() {
	case "basic", "ssh_password", "digest", "ntlm":
		return c.Username, c.Password, true
	case "bearer":
		return "", c.Token, true
	}
	return "", "", false
}

// BasicHeader returns a Basic authorization header value.
func BasicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// LoadKey loads inline PEM or reads a key file through the file policy.
func LoadKey(env Env, v string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") || strings.HasPrefix(strings.TrimSpace(v), "{") {
		return []byte(v), nil
	}
	if env.Files == nil {
		return nil, fmt.Errorf("key file access not configured")
	}
	return env.Files.ReadSmall(v, 1<<20)
}
