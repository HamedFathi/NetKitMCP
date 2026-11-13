// Package wsx holds WebSocket client helpers over github.com/coder/websocket.
// The handshake always runs through a caller-supplied (guarded) HTTP client,
// so the SSRF guard, TLS options, proxy and auth apply to it.
package wsx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Options configure one WebSocket dial.
type Options struct {
	// URL is a ws, wss, http or https URL.
	URL string
	// HTTPClient performs the handshake. It must use an HTTP/1.1 transport
	// (http.Transport returns writable bodies for 101 responses).
	HTTPClient *http.Client
	// Header holds extra handshake headers.
	Header http.Header
	// Origin, when set, is sent as the Origin header.
	Origin string
	// Subprotocols are offered in Sec-WebSocket-Protocol.
	Subprotocols []string
	// Compression negotiates permessage-deflate.
	Compression bool
	// ReadLimit bounds a single incoming message (0 = 1 MiB).
	ReadLimit int64
}

// HandshakeInfo describes the handshake response.
type HandshakeInfo struct {
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Subprotocol string            `json:"subprotocol,omitempty"`
	Extensions  string            `json:"extensions,omitempty"`
	Headers     map[string]string `json:"headers"`
}

// NormalizeURL validates a WebSocket URL, converting http/https to ws/wss.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "http":
		u.Scheme = "ws"
	case "wss", "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported URL scheme %q (use ws, wss, http or https)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("url %q has no host", raw)
	}
	return u.String(), nil
}

// HTTPURL converts a ws/wss URL into the equivalent http/https URL.
func HTTPURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "http":
		u.Scheme = "http"
	case "wss", "https":
		u.Scheme = "https"
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return u.String(), nil
}

// Dial performs the WebSocket handshake.
func Dial(ctx context.Context, o Options) (*websocket.Conn, *HandshakeInfo, error) {
	u, err := NormalizeURL(o.URL)
	if err != nil {
		return nil, nil, err
	}
	if o.HTTPClient == nil {
		return nil, nil, errors.New("wsx: HTTPClient is required")
	}
	h := http.Header{}
	for k, vs := range o.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	if o.Origin != "" {
		h.Set("Origin", o.Origin)
	}
	dopts := &websocket.DialOptions{
		HTTPClient:   o.HTTPClient,
		HTTPHeader:   h,
		Subprotocols: o.Subprotocols,
	}
	if o.Compression {
		dopts.CompressionMode = websocket.CompressionContextTakeover
	}
	conn, resp, err := websocket.Dial(ctx, u, dopts)
	if err != nil {
		return nil, nil, handshakeError(err, resp)
	}
	limit := o.ReadLimit
	if limit <= 0 {
		limit = 1 << 20
	}
	conn.SetReadLimit(limit)
	info := &HandshakeInfo{URL: redact.URL(u), Status: resp.StatusCode, Subprotocol: conn.Subprotocol(),
		Extensions: resp.Header.Get("Sec-WebSocket-Extensions"), Headers: redact.Headers(resp.Header)}
	return conn, info, nil
}

func handshakeError(err error, resp *http.Response) error {
	if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket handshake failed: %w", err)
	}
	var body string
	if resp.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		body = strings.TrimSpace(string(b))
	}
	msg := fmt.Sprintf("websocket handshake failed: server answered HTTP %d %s instead of 101 Switching Protocols",
		resp.StatusCode, http.StatusText(resp.StatusCode))
	if body != "" {
		msg += ": " + body
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		msg += " (check auth, headers and origin)"
	}
	return errors.New(msg)
}

// MessageType returns the coder/websocket message type for "text"/"binary".
func MessageType(kind string) (websocket.MessageType, error) {
	switch strings.ToLower(kind) {
	case "text":
		return websocket.MessageText, nil
	case "binary":
		return websocket.MessageBinary, nil
	}
	return 0, fmt.Errorf("message type must be text or binary, got %q", kind)
}

// TypeName returns "text" or "binary".
func TypeName(t websocket.MessageType) string {
	if t == websocket.MessageBinary {
		return "binary"
	}
	return "text"
}

// Message converts a frame into a stream message (text as text, binary as base64).
func Message(dir string, t websocket.MessageType, data []byte) types.StreamMessage {
	m := types.StreamMessage{Dir: dir, Type: TypeName(t)}
	if t == websocket.MessageText {
		m.Data, m.Encoding = string(data), "text"
	} else {
		m.Data, m.Encoding = base64.StdEncoding.EncodeToString(data), "base64"
	}
	if m.Meta == nil {
		m.Meta = map[string]any{}
	}
	m.Meta["size_bytes"] = len(data)
	return m
}

// CloseInfo extracts the close code/reason from a read error (nil when the
// error is not a close frame).
func CloseInfo(err error) *types.CloseInfo {
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		return &types.CloseInfo{Code: int(ce.Code), Reason: ce.Reason}
	}
	return nil
}

// ValidateCloseCode checks that code may be sent in a close frame.
func ValidateCloseCode(code int) error {
	switch {
	case code == 1000, code >= 1001 && code <= 1003, code >= 1007 && code <= 1014, code >= 3000 && code <= 4999:
		return nil
	}
	return fmt.Errorf("close_code %d cannot be sent (use 1000-1003, 1007-1014 or 3000-4999)", code)
}
