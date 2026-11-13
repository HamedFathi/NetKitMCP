// Package connectrpc is a small client for the Connect protocol
// (https://connectrpc.com/docs/protocol): unary calls with JSON or binary
// protobuf bodies, and server-streaming calls using length-prefixed
// envelopes whose final 0x02-flagged message carries the end-of-stream JSON
// (error and trailing metadata). Framing is shared with package grpcweb.
package connectrpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/grpcweb"
)

// ProtocolVersion is sent as Connect-Protocol-Version.
const ProtocolVersion = "1"

// Codec names.
const (
	CodecJSON  = "json"
	CodecProto = "proto"
)

// Request describes one Connect call.
type Request struct {
	// URL is the full endpoint URL, ending in /package.Service/Method.
	URL string
	// Codec is "json" (default) or "proto".
	Codec string
	// Message is the serialized request message in the codec's format.
	Message []byte
	// Header holds extra request headers.
	Header http.Header
	// Timeout, when > 0, is sent as Connect-Timeout-Ms.
	Timeout time.Duration
	// Streaming selects the server-streaming protocol.
	Streaming bool
	// MaxMessageSize bounds each response message (0 = 16 MiB).
	MaxMessageSize int
	// UserAgent, when set, is sent as User-Agent.
	UserAgent string
}

// Error is a Connect error.
type Error struct {
	Code    string        `json:"code"`
	Message string        `json:"message,omitempty"`
	Details []ErrorDetail `json:"details,omitempty"`
}

// ErrorDetail is one error detail: a protobuf message type name and its
// base64-encoded (padding optional) binary value.
type ErrorDetail struct {
	Type  string          `json:"type"`
	Value string          `json:"value"`
	Debug json.RawMessage `json:"debug,omitempty"`
}

// EndStream is the payload of the final streaming envelope.
type EndStream struct {
	Error    *Error              `json:"error,omitempty"`
	Metadata map[string][]string `json:"metadata,omitempty"`
}

// Result describes a finished call.
type Result struct {
	HTTPStatus int
	Header     http.Header
	Trailer    http.Header
	// Error is nil on success.
	Error    *Error
	Messages int
	Stopped  bool
	TLS      *tls.ConnectionState
}

// ContentType returns the request content type for a codec and mode.
func ContentType(codec string, streaming bool) string {
	if codec == "" {
		codec = CodecJSON
	}
	if streaming {
		return "application/connect+" + codec
	}
	return "application/" + codec
}

// Call performs a Connect call. onMessage receives each response message
// (in the codec's format); returning false stops reading.
func Call(ctx context.Context, hc *http.Client, req Request, onMessage func([]byte) bool) (*Result, error) {
	codec := req.Codec
	if codec == "" {
		codec = CodecJSON
	}
	if codec != CodecJSON && codec != CodecProto {
		return nil, fmt.Errorf("connect codec must be json or proto, got %q", codec)
	}
	max := req.MaxMessageSize
	if max <= 0 {
		max = grpcweb.DefaultMaxFrame
	}
	body := req.Message
	if req.Streaming {
		body = grpcweb.EncodeFrame(grpcweb.FlagData, req.Message)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	hreq.Header.Set("Content-Type", ContentType(codec, req.Streaming))
	hreq.Header.Set("Connect-Protocol-Version", ProtocolVersion)
	if req.UserAgent != "" && hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", req.UserAgent)
	}
	if req.Timeout > 0 {
		ms := req.Timeout.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		hreq.Header.Set("Connect-Timeout-Ms", strconv.FormatInt(ms, 10))
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res := &Result{HTTPStatus: resp.StatusCode, Header: http.Header{}, Trailer: http.Header{}, TLS: resp.TLS}
	for k, vs := range resp.Header {
		if !req.Streaming && strings.HasPrefix(k, "Trailer-") {
			res.Trailer[strings.TrimPrefix(k, "Trailer-")] = vs
			continue
		}
		res.Header[k] = vs
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
		res.Error = ParseError(resp.StatusCode, data)
		return res, nil
	}
	if !req.Streaming {
		data, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
		if err != nil {
			return res, fmt.Errorf("read response: %w", err)
		}
		if len(data) > max {
			return res, fmt.Errorf("response message exceeds %d bytes", max)
		}
		res.Messages = 1
		if onMessage != nil {
			onMessage(data)
		}
		return res, nil
	}

	enc := resp.Header.Get("Connect-Content-Encoding")
	for {
		f, err := grpcweb.ReadFrame(resp.Body, max)
		if err != nil {
			if errors.Is(err, io.EOF) {
				res.Error = &Error{Code: "unknown", Message: "stream ended without an end-of-stream message"}
				return res, nil
			}
			return res, fmt.Errorf("read Connect envelope: %w", err)
		}
		data, err := grpcweb.Decompress(f, enc, max)
		if err != nil {
			return res, err
		}
		if f.IsEndStream() {
			var es EndStream
			if len(bytes.TrimSpace(data)) > 0 {
				if err := json.Unmarshal(data, &es); err != nil {
					return res, fmt.Errorf("parse end-of-stream message: %w", err)
				}
			}
			for k, vs := range es.Metadata {
				res.Trailer[http.CanonicalHeaderKey(k)] = vs
			}
			res.Error = es.Error
			if res.Error != nil && res.Error.Code == "" {
				res.Error.Code = "unknown"
			}
			return res, nil
		}
		res.Messages++
		if onMessage != nil && !onMessage(data) {
			res.Stopped = true
			return res, nil
		}
	}
}

// ParseError decodes a unary error body, falling back to the HTTP status.
func ParseError(httpStatus int, body []byte) *Error {
	var e Error
	if err := json.Unmarshal(body, &e); err == nil && e.Code != "" {
		return &e
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	if msg == "" {
		msg = http.StatusText(httpStatus)
	}
	return &Error{Code: CodeFromHTTP(httpStatus), Message: msg}
}

// EncodeEndStream renders an end-of-stream envelope (used by tests and
// in-process servers).
func EncodeEndStream(es EndStream) []byte {
	b, _ := json.Marshal(es)
	return grpcweb.EncodeFrame(grpcweb.FlagEndStream, b)
}

// codeNames lists Connect codes by their gRPC numeric value.
var codeNames = []string{
	"ok", "canceled", "unknown", "invalid_argument", "deadline_exceeded", "not_found",
	"already_exists", "permission_denied", "resource_exhausted", "failed_precondition",
	"aborted", "out_of_range", "unimplemented", "internal", "unavailable", "data_loss",
	"unauthenticated",
}

// CodeNumber returns the gRPC numeric code for a Connect code name (2 =
// unknown for unrecognised names).
func CodeNumber(name string) int {
	name = strings.ToLower(name)
	if name == "cancelled" {
		name = "canceled"
	}
	for i, n := range codeNames {
		if n == name {
			return i
		}
	}
	return 2
}

// CodeName returns the Connect name for a gRPC numeric code.
func CodeName(code int) string {
	if code >= 0 && code < len(codeNames) {
		return codeNames[code]
	}
	return "unknown"
}

// HTTPStatus returns the HTTP status a Connect server uses for a code.
func HTTPStatus(code string) int {
	switch strings.ToLower(code) {
	case "canceled":
		return 499
	case "invalid_argument", "out_of_range", "failed_precondition":
		return http.StatusBadRequest
	case "deadline_exceeded":
		return http.StatusGatewayTimeout
	case "not_found", "unimplemented":
		return http.StatusNotFound
	case "already_exists", "aborted":
		return http.StatusConflict
	case "permission_denied":
		return http.StatusForbidden
	case "resource_exhausted":
		return http.StatusTooManyRequests
	case "unavailable":
		return http.StatusServiceUnavailable
	case "unauthenticated":
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// CodeFromHTTP infers a Connect code from an HTTP status when the error
// body carries none.
func CodeFromHTTP(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "internal"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "permission_denied"
	case http.StatusNotFound:
		return "unimplemented"
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "unavailable"
	default:
		return "unknown"
	}
}
