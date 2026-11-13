// Package grpcx holds the protocol side of the gRPC tools: connections,
// descriptor sources (server reflection, .proto files compiled in-process,
// descriptor sets), dynamic JSON <-> protobuf conversion, unary invocation,
// bounded one-shot streams and interactive stream sessions.
package grpcx

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// DialConfig configures a client connection.
type DialConfig struct {
	// Target is host:port.
	Target string
	// Dial opens the TCP connection (the SSRF-guarded dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS is the client TLS configuration; nil means plaintext (h2c).
	TLS *tls.Config
	// Authority overrides the :authority pseudo-header.
	Authority string
	// MaxMessageSize bounds sent and received messages (0 = grpc default).
	MaxMessageSize int
	// UserAgent is prepended to grpc-go's user agent.
	UserAgent string
}

// Dial creates a lazily connecting client. The "passthrough" resolver is
// used so the guarded dialer receives the host:port as given and performs
// its own resolution and IP checks.
func Dial(cfg DialConfig) (*grpc.ClientConn, error) {
	if cfg.Dial == nil {
		return nil, fmt.Errorf("grpcx: a dialer is required")
	}
	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return cfg.Dial(ctx, "tcp", addr)
		}),
	}
	if cfg.TLS != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(cfg.TLS)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if cfg.Authority != "" {
		opts = append(opts, grpc.WithAuthority(cfg.Authority))
	}
	if cfg.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(cfg.UserAgent))
	}
	if cfg.MaxMessageSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxMessageSize),
			grpc.MaxCallSendMsgSize(cfg.MaxMessageSize)))
	}
	return grpc.NewClient("passthrough:///"+cfg.Target, opts...)
}

// ParseTarget normalises a target into host:port. It accepts bare
// host:port, grpc:// (plaintext), grpcs:// (TLS), http:// and https://
// prefixes and dns:/// style targets. plaintext is the caller's choice; a
// scheme overrides it. A missing port defaults to 443 (TLS) or 80.
func ParseTarget(raw string, plaintext bool) (hostport string, usePlaintext bool, err error) {
	t := strings.TrimSpace(raw)
	usePlaintext = plaintext
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "grpcs://"), strings.HasPrefix(lower, "https://"):
		usePlaintext = false
		t = t[strings.Index(t, "://")+3:]
	case strings.HasPrefix(lower, "grpc://"), strings.HasPrefix(lower, "http://"):
		usePlaintext = true
		t = t[strings.Index(t, "://")+3:]
	case strings.HasPrefix(lower, "dns:///"):
		t = t[len("dns:///"):]
	case strings.HasPrefix(lower, "passthrough:///"):
		t = t[len("passthrough:///"):]
	}
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	if t == "" {
		return "", false, fmt.Errorf("target is empty; use host:port")
	}
	if _, _, err := net.SplitHostPort(t); err != nil {
		port := "443"
		if usePlaintext {
			port = "80"
		}
		host := strings.Trim(t, "[]")
		if strings.Contains(host, ":") && !strings.Contains(t, "]") && net.ParseIP(host) == nil {
			return "", false, fmt.Errorf("invalid target %q; use host:port", raw)
		}
		t = net.JoinHostPort(host, port)
	}
	return t, usePlaintext, nil
}

// OutgoingMD builds request metadata from user metadata and auth headers.
// Keys are lower-cased; values of keys ending in "-bin" are base64-decoded
// (grpc-go re-encodes them on the wire).
func OutgoingMD(user map[string]string, authHeaders http.Header) (metadata.MD, error) {
	md := metadata.MD{}
	for k, v := range user {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		if strings.HasSuffix(key, "-bin") {
			b, err := types.DecodeBase64(v)
			if err != nil {
				return nil, fmt.Errorf("metadata %q: -bin values must be base64", k)
			}
			v = string(b)
		}
		md.Append(key, v)
	}
	for k, vs := range authHeaders {
		key := strings.ToLower(k)
		md.Set(key, vs...)
	}
	return md, nil
}

// MDToMap flattens metadata for results: values are joined with ", ",
// binary values are base64-encoded and secrets are redacted.
func MDToMap(md metadata.MD) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(md))
	for k := range md {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := md[k]
		if strings.HasSuffix(k, "-bin") {
			enc := make([]string, len(vs))
			for i, v := range vs {
				enc[i] = base64.StdEncoding.EncodeToString([]byte(v))
			}
			vs = enc
		}
		v := strings.Join(vs, ", ")
		if redact.IsSensitiveName(k) {
			v = redact.Value(v)
		}
		out[k] = v
	}
	return out
}

// HeaderToMap flattens HTTP headers (lower-cased keys) with redaction.
func HeaderToMap(h http.Header) map[string]string {
	md := metadata.MD{}
	for k, vs := range h {
		md[strings.ToLower(k)] = vs
	}
	// HTTP -bin values are already base64 text; avoid double encoding.
	out := map[string]string{}
	for k, vs := range md {
		v := strings.Join(vs, ", ")
		if redact.IsSensitiveName(k) {
			v = redact.Value(v)
		}
		out[k] = v
	}
	return out
}
