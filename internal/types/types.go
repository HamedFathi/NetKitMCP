// Package types holds the argument and result shapes shared by all tools.
package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
)

// TLSOptions are the TLS knobs shared by every TLS-capable protocol.
// Certificate and key fields accept inline PEM or a path inside an allowed
// read directory.
type TLSOptions struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" jsonschema:"skip server certificate verification (flagged in the result)"`
	CACert             string `json:"ca_cert,omitempty" jsonschema:"extra CA certificate(s): inline PEM or file path"`
	ClientCert         string `json:"client_cert,omitempty" jsonschema:"client certificate for mTLS: inline PEM or file path"`
	ClientKey          string `json:"client_key,omitempty" jsonschema:"client private key for mTLS: inline PEM or file path"`
	ServerName         string `json:"server_name,omitempty" jsonschema:"override TLS SNI / verification name"`
}

// NetOptions are the options shared by every network tool.
type NetOptions struct {
	TLSOptions
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty" jsonschema:"overall timeout in seconds (default 30)"`
	AllowPrivate   bool    `json:"allow_private,omitempty" jsonschema:"permit loopback/private/link-local targets (subject to server policy)"`
}

// HTTPOptions are the options shared by HTTP-based tools.
type HTTPOptions struct {
	NetOptions
	FollowRedirects  *bool  `json:"follow_redirects,omitempty" jsonschema:"follow redirects (default true)"`
	MaxRedirects     int    `json:"max_redirects,omitempty" jsonschema:"maximum redirects to follow (default 10)"`
	Proxy            string `json:"proxy,omitempty" jsonschema:"proxy URL (http, https or socks5)"`
	MaxResponseBytes int64  `json:"max_response_bytes,omitempty" jsonschema:"maximum response body bytes returned inline (default 1 MiB)"`
	HTTPVersion      string `json:"http_version,omitempty" jsonschema:"1.1, 2 or 3 (default: negotiate 1.1/2)"`
}

// Payload is a value supplied as text, JSON, base64 or a file reference.
// At most one field may be set.
type Payload struct {
	Text   *string `json:"text,omitempty" jsonschema:"UTF-8 text payload"`
	JSON   any     `json:"json,omitempty" jsonschema:"JSON payload (serialized compactly)"`
	Base64 string  `json:"base64,omitempty" jsonschema:"binary payload as base64 (small payloads only)"`
	File   string  `json:"file,omitempty" jsonschema:"path of a file inside an allowed read directory"`
}

// IsZero reports whether no field is set.
func (p *Payload) IsZero() bool {
	return p == nil || (p.Text == nil && p.JSON == nil && p.Base64 == "" && p.File == "")
}

// Validate ensures at most one field is set.
func (p *Payload) Validate() error {
	if p == nil {
		return nil
	}
	n := 0
	if p.Text != nil {
		n++
	}
	if p.JSON != nil {
		n++
	}
	if p.Base64 != "" {
		n++
	}
	if p.File != "" {
		n++
	}
	if n > 1 {
		return fmt.Errorf("payload: set only one of text, json, base64, file")
	}
	return nil
}

// Timing is a request timing breakdown in milliseconds.
type Timing struct {
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	TLS     float64 `json:"tls"`
	TTFB    float64 `json:"ttfb"`
	Total   float64 `json:"total"`
}

// TLSInfo summarises the negotiated TLS connection.
type TLSInfo struct {
	Version            string `json:"version"`
	Cipher             string `json:"cipher"`
	PeerCN             string `json:"peer_cn,omitempty"`
	ALPN               string `json:"alpn,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// FileInfo describes a transferred file.
type FileInfo = fileio.FileInfo

// HTTPResponse is the HTTP-like result shape.
type HTTPResponse struct {
	Status       int               `json:"status"`
	StatusText   string            `json:"status_text"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"body_encoding"`
	ContentType  string            `json:"content_type,omitempty"`
	SavedTo      *FileInfo         `json:"saved_to"`
	FinalURL     string            `json:"final_url"`
	Protocol     string            `json:"protocol"`
	TimingMS     Timing            `json:"timing_ms"`
	TLS          *TLSInfo          `json:"tls,omitempty"`
	SizeBytes    int64             `json:"size_bytes"`
	Truncated    bool              `json:"truncated"`
	Redirects    []string          `json:"redirects,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
}

// StreamMessage is one message in a message-stream result.
type StreamMessage struct {
	Seq      int               `json:"seq"`
	Dir      string            `json:"dir"`
	TS       string            `json:"ts"`
	Type     string            `json:"type"`
	Event    string            `json:"event,omitempty"`
	ID       string            `json:"id,omitempty"`
	Topic    string            `json:"topic,omitempty"`
	Data     string            `json:"data"`
	Encoding string            `json:"encoding"`
	Meta     map[string]any    `json:"meta,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// CloseInfo describes how a stream was closed.
type CloseInfo struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

// Ended-by values.
const (
	EndedMaxMessages = "max_messages"
	EndedMaxDuration = "max_duration"
	EndedIdle        = "idle"
	EndedPeerClosed  = "peer_closed"
	EndedStopEvent   = "stop_event"
	EndedError       = "error"
	EndedComplete    = "complete"
	// EndedDrained: a receive returned the buffered messages before its wait expired.
	EndedDrained = "drained"
)

// StreamResult is the message-stream result shape.
type StreamResult struct {
	Messages  []StreamMessage `json:"messages"`
	EndedBy   string          `json:"ended_by"`
	Close     *CloseInfo      `json:"close,omitempty"`
	Error     string          `json:"error,omitempty"`
	Truncated bool            `json:"truncated"`
	Dropped   int             `json:"dropped,omitempty"`
	Meta      map[string]any  `json:"meta,omitempty"`
}

// RemoteInfo describes the remote side of a transfer.
type RemoteInfo struct {
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	ETag     string `json:"etag,omitempty"`
	Path     string `json:"path,omitempty"`
}

// TransferResult is the upload/download result shape.
type TransferResult struct {
	File             FileInfo `json:"file"`
	BytesTransferred int64    `json:"bytes_transferred"`
	ResumedFrom      int64    `json:"resumed_from"`
	Parts            int      `json:"parts"`
	TimingMS         struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Remote   RemoteInfo     `json:"remote"`
	Response *HTTPResponse  `json:"response,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

// StreamLimits bound one-shot stream collection.
type StreamLimits struct {
	MaxMessages        int     `json:"max_messages,omitempty" jsonschema:"stop after this many received messages (default 100)"`
	MaxDurationSeconds float64 `json:"max_duration_seconds,omitempty" jsonschema:"stop after this many seconds (default 10)"`
	IdleTimeoutSeconds float64 `json:"idle_timeout_seconds,omitempty" jsonschema:"stop when no message arrives for this many seconds (default: none)"`
}

// MS converts a duration to fractional milliseconds rounded to 0.01.
func MS(d time.Duration) float64 {
	return float64(d.Microseconds()/10) / 100
}

// Now returns an RFC3339Nano UTC timestamp.
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// EncodeBody returns data as text when it is valid UTF-8 and looks textual,
// otherwise base64.
func EncodeBody(data []byte, contentType string) (string, string) {
	if IsTextual(data, contentType) {
		return string(data), "text"
	}
	return base64.StdEncoding.EncodeToString(data), "base64"
}

// IsTextual reports whether data should be returned as text.
func IsTextual(data []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if ct != "" {
		for _, bin := range []string{"image/", "audio/", "video/", "application/octet-stream", "application/pdf",
			"application/zip", "application/gzip", "application/x-protobuf", "application/grpc", "application/vnd.ms-", "font/"} {
			if strings.HasPrefix(ct, bin) {
				return false
			}
		}
	}
	if !utf8.Valid(data) {
		return false
	}
	// Reject control characters other than common whitespace.
	ctrl := 0
	for _, r := range string(data) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' && r != '\f' {
			ctrl++
		}
	}
	return ctrl == 0 || ctrl*100 < len(data)
}

// ToJSONValue returns v unmarshaled as JSON if data is valid JSON, else nil.
func ToJSONValue(data []byte) (any, bool) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	return v, true
}

// BoolDefault returns *b or def when nil.
func BoolDefault(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}
