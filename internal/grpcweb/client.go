package grpcweb

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Content types.
const (
	ContentTypeProto = "application/grpc-web+proto"
	ContentTypeText  = "application/grpc-web-text+proto"
)

// Request describes one gRPC-Web call (unary or server-streaming).
type Request struct {
	// URL is the full endpoint URL, ending in /package.Service/Method.
	URL string
	// Text selects application/grpc-web-text (base64 body) instead of binary.
	Text bool
	// Message is the serialized request message.
	Message []byte
	// Header holds extra request headers / metadata.
	Header http.Header
	// Timeout, when > 0, is sent as the grpc-timeout header.
	Timeout time.Duration
	// MaxMessageSize bounds each response frame (0 = DefaultMaxFrame).
	MaxMessageSize int
	// UserAgent, when set, is sent as User-Agent and X-User-Agent.
	UserAgent string
}

// Status is a gRPC status received over gRPC-Web.
type Status struct {
	Code       int
	Message    string
	DetailsBin []byte // serialized google.rpc.Status from grpc-status-details-bin
}

// Result describes a finished call.
type Result struct {
	HTTPStatus int
	Header     http.Header
	Trailer    http.Header
	Status     *Status
	Messages   int
	// Stopped is true when onMessage asked to stop before the stream ended.
	Stopped bool
	TLS     *tls.ConnectionState
}

// Call sends req with hc and invokes onMessage for every response message
// in order. Returning false from onMessage stops reading (the call is then
// abandoned). Transport failures are returned as errors; gRPC failures are
// reported in Result.Status.
func Call(ctx context.Context, hc *http.Client, req Request, onMessage func([]byte) bool) (*Result, error) {
	body := EncodeFrame(FlagData, req.Message)
	ct := ContentTypeProto
	if req.Text {
		ct = ContentTypeText
		body = EncodeText(body)
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
	hreq.Header.Set("Content-Type", ct)
	hreq.Header.Set("Accept", ct)
	hreq.Header.Set("X-Grpc-Web", "1")
	if req.UserAgent != "" {
		if hreq.Header.Get("User-Agent") == "" {
			hreq.Header.Set("User-Agent", req.UserAgent)
		}
		hreq.Header.Set("X-User-Agent", req.UserAgent)
	}
	if req.Timeout > 0 {
		hreq.Header.Set("Grpc-Timeout", EncodeTimeout(req.Timeout))
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res := &Result{HTTPStatus: resp.StatusCode, Header: resp.Header, Trailer: http.Header{}, TLS: resp.TLS}

	// Trailers-only responses carry the status in the headers.
	if st := StatusFromHeader(resp.Header); st != nil {
		res.Status = st
	}
	if resp.StatusCode != http.StatusOK {
		if res.Status == nil {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			res.Status = &Status{Code: HTTPToCode(resp.StatusCode),
				Message: strings.TrimSpace(fmt.Sprintf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(msg))))}
		}
		return res, nil
	}
	rct := strings.ToLower(resp.Header.Get("Content-Type"))
	var r io.Reader = resp.Body
	if strings.HasPrefix(rct, "application/grpc-web-text") {
		r = NewTextReader(resp.Body)
	} else if rct != "" && !strings.HasPrefix(rct, "application/grpc-web") && res.Status == nil {
		return nil, fmt.Errorf("unexpected response content type %q (is this a gRPC-Web endpoint?)", resp.Header.Get("Content-Type"))
	}
	enc := resp.Header.Get("Grpc-Encoding")
	for {
		f, err := ReadFrame(r, req.MaxMessageSize)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return res, fmt.Errorf("read gRPC-Web frame: %w", err)
		}
		data, err := Decompress(f, enc, req.MaxMessageSize)
		if err != nil {
			return res, err
		}
		if f.IsTrailer() {
			tr, err := ParseTrailers(data)
			if err != nil {
				return res, err
			}
			res.Trailer = tr
			if st := StatusFromHeader(tr); st != nil {
				res.Status = st
			}
			break
		}
		res.Messages++
		if onMessage != nil && !onMessage(data) {
			res.Stopped = true
			return res, nil
		}
	}
	// Some servers (or proxies) send real HTTP trailers instead of a frame.
	if res.Status == nil {
		if st := StatusFromHeader(resp.Trailer); st != nil {
			res.Status = st
			res.Trailer = resp.Trailer
		}
	}
	if res.Status == nil {
		res.Status = &Status{Code: 2, Message: "response ended without a grpc-status trailer"}
	}
	return res, nil
}

// StatusFromHeader extracts grpc-status / grpc-message /
// grpc-status-details-bin from h (nil when grpc-status is absent).
func StatusFromHeader(h http.Header) *Status {
	v := h.Get("Grpc-Status")
	if v == "" {
		return nil
	}
	code, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		code = 2
	}
	st := &Status{Code: code, Message: DecodeGRPCMessage(h.Get("Grpc-Message"))}
	if d := h.Get("Grpc-Status-Details-Bin"); d != "" {
		if b, err := DecodeBinaryHeader(d); err == nil {
			st.DetailsBin = b
		}
	}
	return st
}

// DecodeGRPCMessage undoes the percent-encoding of grpc-message.
func DecodeGRPCMessage(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// EncodeGRPCMessage percent-encodes a grpc-message value.
func EncodeGRPCMessage(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e && c != '%' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// DecodeBinaryHeader decodes a -bin header value (padded or unpadded base64).
func DecodeBinaryHeader(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "="))
}

// EncodeTimeout renders a grpc-timeout header value.
func EncodeTimeout(d time.Duration) string {
	ms := d.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	if ms < 1e8 {
		return strconv.FormatInt(ms, 10) + "m"
	}
	return strconv.FormatInt(int64(d.Seconds()), 10) + "S"
}

// HTTPToCode maps an HTTP status to a gRPC code when no grpc-status is present.
func HTTPToCode(status int) int {
	switch status {
	case http.StatusBadRequest:
		return 13 // Internal
	case http.StatusUnauthorized:
		return 16 // Unauthenticated
	case http.StatusForbidden:
		return 7 // PermissionDenied
	case http.StatusNotFound:
		return 12 // Unimplemented
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return 14 // Unavailable
	default:
		return 2 // Unknown
	}
}
