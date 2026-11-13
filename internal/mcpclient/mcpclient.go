// Package mcpclient connects to remote MCP servers over streamable HTTP or
// the legacy HTTP+SSE transport, using the official go-sdk client. Spawning
// stdio servers is deliberately unsupported (it would mean executing
// arbitrary processes).
package mcpclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Transport names.
const (
	TransportStreamable = "streamable_http"
	TransportSSE        = "sse"
)

// NormalizeTransport maps user input to a transport name.
func NormalizeTransport(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "streamable", "streamable_http", "streamable-http", "http", "https":
		return TransportStreamable, nil
	case "sse", "http+sse", "legacy_sse":
		return TransportSSE, nil
	case "stdio", "command", "process":
		return "", errors.New("stdio MCP servers are not supported: netkit-mcp never spawns processes; point url at an HTTP MCP endpoint instead")
	}
	return "", fmt.Errorf("unknown transport %q (use streamable_http or sse)", s)
}

// ValidateEndpoint checks that endpoint is an absolute http(s) URL and
// rejects anything that looks like a command line.
func ValidateEndpoint(endpoint string) error {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return errors.New("url is required (the remote MCP server's HTTP endpoint)")
	}
	u, err := url.Parse(e)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("url must be an http(s) MCP endpoint such as https://example.com/mcp, got %q; spawning stdio servers (commands) is not supported", endpoint)
	}
	return nil
}

// Options configures a connection.
type Options struct {
	Endpoint   string
	Transport  string // TransportStreamable (default) or TransportSSE
	HTTPClient *http.Client
	Headers    http.Header // extra headers on every request
	MaxRetries int         // streamable reconnect attempts (default 1; negative disables)
	ClientName string
}

type headerTransport struct {
	base http.RoundTripper
	h    http.Header
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, vs := range t.h {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return t.base.RoundTrip(req)
}

// Connect opens a client session. The caller must Close it.
func Connect(ctx context.Context, o Options) (*mcp.ClientSession, error) {
	if err := ValidateEndpoint(o.Endpoint); err != nil {
		return nil, err
	}
	tname, err := NormalizeTransport(o.Transport)
	if err != nil {
		return nil, err
	}
	hc := o.HTTPClient
	if hc == nil {
		return nil, errors.New("mcpclient: an HTTP client is required")
	}
	if len(o.Headers) > 0 {
		base := hc.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		c := *hc
		c.Transport = &headerTransport{base: base, h: o.Headers}
		hc = &c
	}
	var t mcp.Transport
	switch tname {
	case TransportSSE:
		t = &mcp.SSEClientTransport{Endpoint: o.Endpoint, HTTPClient: hc}
	default:
		retries := o.MaxRetries
		if retries == 0 {
			retries = 1
		}
		t = &mcp.StreamableClientTransport{Endpoint: o.Endpoint, HTTPClient: hc, DisableStandaloneSSE: true, MaxRetries: retries}
	}
	name := o.ClientName
	if name == "" {
		name = "netkit-mcp"
	}
	client := mcp.NewClient(&mcp.Implementation{Name: name, Version: "1"}, nil)
	cs, err := client.Connect(ctx, t, nil)
	if err != nil {
		hint := ""
		switch msg := strings.ToLower(err.Error()); {
		case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "401"):
			hint = " (the server requires authentication: set auth, e.g. {\"type\":\"bearer\",\"token\":\"...\"})"
		case strings.Contains(msg, "forbidden") || strings.Contains(msg, "403"):
			hint = " (access denied: check the credentials in auth)"
		case strings.Contains(msg, "not found") || strings.Contains(msg, "404") || strings.Contains(msg, "405"):
			hint = " (check url; for legacy servers try transport=sse with the SSE endpoint)"
		}
		return nil, fmt.Errorf("connect to MCP server %s (%s): %w%s", o.Endpoint, tname, err, hint)
	}
	return cs, nil
}

// ServerInfo describes the connected server.
type ServerInfo struct {
	Name            string `json:"name,omitempty"`
	Title           string `json:"title,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Instructions    string `json:"instructions,omitempty"`
	HasTools        bool   `json:"has_tools"`
}

// Server returns information from the session handshake (nil if unknown).
func Server(cs *mcp.ClientSession) *ServerInfo {
	ir := cs.InitializeResult()
	if ir == nil {
		return nil
	}
	si := &ServerInfo{ProtocolVersion: ir.ProtocolVersion, Instructions: ir.Instructions}
	if ir.ServerInfo != nil {
		si.Name, si.Title, si.Version = ir.ServerInfo.Name, ir.ServerInfo.Title, ir.ServerInfo.Version
	}
	if ir.Capabilities != nil && ir.Capabilities.Tools != nil {
		si.HasTools = true
	}
	return si
}

// ListAll lists tools, following pagination for at most maxPages pages.
// It reports whether more pages remained.
func ListAll(ctx context.Context, cs *mcp.ClientSession, maxPages int) ([]*mcp.Tool, int, bool, error) {
	if maxPages <= 0 {
		maxPages = 50
	}
	var out []*mcp.Tool
	cursor := ""
	for page := 1; page <= maxPages; page++ {
		res, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return out, page - 1, false, fmt.Errorf("tools/list: %w", err)
		}
		out = append(out, res.Tools...)
		if res.NextCursor == "" {
			return out, page, false, nil
		}
		cursor = res.NextCursor
	}
	return out, maxPages, true, nil
}

// ContentItem is one content block of a tool result.
type ContentItem struct {
	Type        string         `json:"type"`
	Text        string         `json:"text,omitempty"`
	MIMEType    string         `json:"mime_type,omitempty"`
	Data        string         `json:"data,omitempty"` // base64 for image/audio/blob
	Encoding    string         `json:"encoding,omitempty"`
	SizeBytes   *int64         `json:"size_bytes,omitempty"`
	SHA256      string         `json:"sha256,omitempty"`
	URI         string         `json:"uri,omitempty"`
	Name        string         `json:"name,omitempty"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Truncated   bool           `json:"truncated,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
}

// Budget bounds how many bytes of text/binary content are returned inline.
type Budget struct{ Remaining int64 }

func (b *Budget) take(n int64) int64 {
	if b == nil {
		return n
	}
	if n > b.Remaining {
		n = max(b.Remaining, 0)
	}
	b.Remaining -= n
	return n
}

func binaryItem(typ, mime string, data []byte, b *Budget) ContentItem {
	size := int64(len(data))
	sum := sha256.Sum256(data)
	it := ContentItem{Type: typ, MIMEType: mime, SizeBytes: &size, SHA256: hex.EncodeToString(sum[:]), Encoding: "base64"}
	if n := b.take(size); n == size {
		it.Data = base64.StdEncoding.EncodeToString(data)
	} else {
		it.Truncated = true
		it.Encoding = ""
	}
	return it
}

func textItem(typ, text string, b *Budget) (string, bool) {
	n := b.take(int64(len(text)))
	if n < int64(len(text)) {
		return text[:n], true
	}
	return text, false
}

// ConvertContent turns SDK content into result items.
func ConvertContent(cs []mcp.Content, b *Budget) []ContentItem {
	out := make([]ContentItem, 0, len(cs))
	for _, c := range cs {
		switch v := c.(type) {
		case *mcp.TextContent:
			t, tr := textItem("text", v.Text, b)
			out = append(out, ContentItem{Type: "text", Text: t, Truncated: tr})
		case *mcp.ImageContent:
			out = append(out, binaryItem("image", v.MIMEType, v.Data, b))
		case *mcp.AudioContent:
			out = append(out, binaryItem("audio", v.MIMEType, v.Data, b))
		case *mcp.ResourceLink:
			out = append(out, ContentItem{Type: "resource_link", URI: v.URI, Name: v.Name, Title: v.Title,
				Description: v.Description, MIMEType: v.MIMEType, SizeBytes: v.Size})
		case *mcp.EmbeddedResource:
			it := ContentItem{Type: "resource"}
			if r := v.Resource; r != nil {
				it.URI, it.MIMEType = r.URI, r.MIMEType
				if r.Blob != nil {
					bi := binaryItem("resource", r.MIMEType, r.Blob, b)
					bi.URI = r.URI
					it = bi
				} else {
					it.Text, it.Truncated = textItem("resource", r.Text, b)
					it.Encoding = "text"
				}
			}
			out = append(out, it)
		default:
			it := ContentItem{Type: "unknown"}
			if raw, err := c.MarshalJSON(); err == nil {
				var m map[string]any
				if json.Unmarshal(raw, &m) == nil {
					if t, ok := m["type"].(string); ok {
						it.Type = t
					}
					delete(m, "data")
					it.Raw = m
				}
			}
			out = append(out, it)
		}
	}
	return out
}
