package apitools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupHTTP, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerGraphQL(s, d)
	registerGraphQLSubscribe(s, d)
	registerJSONRPC(s, d)
	registerXMLRPC(s, d)
	registerSSE(s, d)
	registerFetchWeb(s, d)
}

// checkURL validates an absolute URL with one of the allowed schemes.
func checkURL(raw string, schemes ...string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid url %q: an absolute URL (%s) is required", raw, strings.Join(schemes, ", "))
	}
	u.Scheme = strings.ToLower(u.Scheme)
	for _, s := range schemes {
		if u.Scheme == s {
			return u, nil
		}
	}
	return nil, fmt.Errorf("unsupported URL scheme %q (use %s)", u.Scheme, strings.Join(schemes, " or "))
}

// call is one bounded HTTP exchange through the shared client.
type call struct {
	Method      string
	URL         string
	Headers     map[string]string // user headers (override defaults)
	Defaults    map[string]string // default headers
	Body        io.Reader
	ContentType string
	Read        httpx.ReadOptions
}

// do builds a guarded client, sends the request and reads the response into
// the shared HTTP response shape.
func do(ctx context.Context, d *tools.Deps, opts types.HTTPOptions, a *auth.Config, c call) (*types.HTTPResponse, error) {
	cl, err := d.NewHTTPClient(opts, a)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	ctx, cancel := cl.Context(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, c.Method, c.URL, c.Body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if c.ContentType != "" {
		req.Header.Set("Content-Type", c.ContentType)
	}
	for k, v := range c.Defaults {
		req.Header.Set(k, v)
	}
	applyHeaders(req.Header, c.Headers)
	resp, err := cl.Do(req, c.Read)
	if err != nil {
		return nil, requestError(err, cl)
	}
	return resp, nil
}

func applyHeaders(h http.Header, m map[string]string) {
	for k, v := range m {
		if strings.EqualFold(k, "Host") {
			continue
		}
		h.Set(k, v)
	}
}

// requestError makes transport errors actionable.
func requestError(err error, cl *httpx.Client) error {
	if httpx.IsTimeout(err) {
		return fmt.Errorf("request timed out after %s (raise timeout_seconds): %w", cl.Timeout, err)
	}
	return err
}

// rawBody returns the response body bytes, decoding base64 bodies.
func rawBody(r *types.HTTPResponse) []byte {
	if r.BodyEncoding == "base64" {
		if b, err := types.DecodeBase64(r.Body); err == nil {
			return b
		}
	}
	return []byte(r.Body)
}

// httpSummary is the HTTP envelope shared by the RPC-style tools.
type httpSummary struct {
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	FinalURL    string            `json:"final_url"`
	Protocol    string            `json:"protocol"`
	TimingMS    types.Timing      `json:"timing_ms"`
	TLS         *types.TLSInfo    `json:"tls,omitempty"`
	SizeBytes   int64             `json:"size_bytes"`
	Truncated   bool              `json:"truncated,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
}

func summarize(r *types.HTTPResponse, includeHeaders bool) httpSummary {
	s := httpSummary{
		Status:      r.Status,
		StatusText:  r.StatusText,
		ContentType: r.ContentType,
		FinalURL:    r.FinalURL,
		Protocol:    r.Protocol,
		TimingMS:    r.TimingMS,
		TLS:         r.TLS,
		SizeBytes:   r.SizeBytes,
		Truncated:   r.Truncated,
		Warnings:    r.Warnings,
	}
	if includeHeaders {
		s.Headers = r.Headers
	}
	return s
}

// newCollector builds a bounded collector from stream limits resolved
// against the server configuration.
func newCollector(d *tools.Deps, l types.StreamLimits) *types.Collector {
	n, dur, idle := l.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	return types.NewCollector(n, dur, idle, 0)
}
