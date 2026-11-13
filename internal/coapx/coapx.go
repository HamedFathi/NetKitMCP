// Package coapx is a thin CoAP client on top of github.com/plgd-dev/go-coap/v3.
// The caller dials the socket (through the SSRF guard) and coapx hands it to
// go-coap: UDP via udp.Client(*net.UDPConn), TCP/TLS via tcp.Client(net.Conn).
// Block-wise transfer (RFC 7959) is handled by go-coap. DTLS is not
// supported.
package coapx

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/message/pool"
	"github.com/plgd-dev/go-coap/v3/net/blockwise"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/tcp"
	tcpclient "github.com/plgd-dev/go-coap/v3/tcp/client"
	"github.com/plgd-dev/go-coap/v3/udp"
	udpclient "github.com/plgd-dev/go-coap/v3/udp/client"
)

// Target is a parsed CoAP URL.
type Target struct {
	URL     *url.URL
	Network string // "udp" or "tcp"
	TLS     bool
	Host    string // host:port
	Path    string
	Queries []string
}

// ParseURL parses coap://host[:port]/path?query (UDP, default port 5683),
// coap+tcp:// (TCP, 5683) and coaps+tcp:// (TLS, 5684). coaps:// (DTLS) is
// rejected.
func ParseURL(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "coap://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid CoAP URL: %w", err)
	}
	t := &Target{URL: u}
	port := "5683"
	switch strings.ToLower(u.Scheme) {
	case "coap":
		t.Network = "udp"
	case "coap+tcp":
		t.Network = "tcp"
	case "coaps+tcp":
		t.Network, t.TLS, port = "tcp", true, "5684"
	case "coaps", "coaps+udp":
		return nil, fmt.Errorf("coaps:// (CoAP over DTLS) is not supported; use coap://, coap+tcp:// or coaps+tcp://")
	default:
		return nil, fmt.Errorf("unsupported CoAP scheme %q (use coap, coap+tcp or coaps+tcp)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("CoAP URL %q has no host", raw)
	}
	p := u.Port()
	if p == "" {
		p = port
	}
	t.Host = net.JoinHostPort(u.Hostname(), p)
	t.Path = u.Path
	if t.Path == "" {
		t.Path = "/"
	}
	if u.RawQuery != "" {
		for _, q := range strings.Split(u.RawQuery, "&") {
			if q == "" {
				continue
			}
			if uq, err := url.QueryUnescape(q); err == nil {
				q = uq
			}
			t.Queries = append(t.Queries, q)
		}
	}
	return t, nil
}

var mediaAliases = map[string]message.MediaType{
	"text":         message.TextPlain,
	"text/plain":   message.TextPlain,
	"json":         message.AppJSON,
	"cbor":         message.AppCBOR,
	"xml":          message.AppXML,
	"octet-stream": message.AppOctets,
	"binary":       message.AppOctets,
	"link-format":  message.AppLinkFormat,
	"senml+json":   message.AppSenmlJSON,
	"senml+cbor":   message.AppSenmlCbor,
}

// ParseMediaType accepts a number, a MIME type (application/json) or a
// short alias (json, cbor, text, xml, link-format, ...).
func ParseMediaType(s string) (message.MediaType, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return message.MediaType(n), nil
	}
	if mt, ok := mediaAliases[s]; ok {
		return mt, nil
	}
	if mt, ok := mediaAliases[strings.TrimPrefix(s, "application/")]; ok {
		return mt, nil
	}
	if mt, err := message.ToMediaType(s); err == nil {
		return mt, nil
	}
	return 0, fmt.Errorf("unknown content format %q (use a number or e.g. text/plain, application/json, application/cbor)", s)
}

// ParseOptionID accepts a number or an option name such as "uri-query",
// "Accept", "ETag", "max-age".
func ParseOptionID(s string) (message.OptionID, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return message.OptionID(n), nil
	}
	norm := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	for id := message.OptionID(1); id < 1000; id++ {
		name := id.String()
		if strings.HasPrefix(name, "Option(") {
			continue
		}
		if strings.ToLower(name) == norm {
			return id, nil
		}
	}
	return 0, fmt.Errorf("unknown CoAP option %q (use a number or a name like uri-query, accept, etag, max-age)", s)
}

// Option is a request option given by name/number and a textual value.
// Integer options take a decimal value, opaque options a hex value
// (optionally 0x-prefixed), string options the value as-is.
type Option struct {
	Name  string
	Value string
}

func encodeOption(o Option) (message.Option, error) {
	id, err := ParseOptionID(o.Name)
	if err != nil {
		return message.Option{}, err
	}
	def, ok := message.CoapOptionDefs[id]
	format := message.ValueOpaque
	if ok {
		format = def.ValueFormat
	}
	switch format {
	case message.ValueEmpty:
		return message.Option{ID: id}, nil
	case message.ValueUint:
		v := o.Value
		if id == message.ContentFormat || id == message.Accept {
			mt, err := ParseMediaType(v)
			if err != nil {
				return message.Option{}, err
			}
			v = strconv.Itoa(int(mt))
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		if err != nil {
			return message.Option{}, fmt.Errorf("option %s needs an unsigned integer value, got %q", id, o.Value)
		}
		buf := make([]byte, 4)
		l, _ := message.EncodeUint32(buf, uint32(n))
		return message.Option{ID: id, Value: buf[:l]}, nil
	case message.ValueString:
		return message.Option{ID: id, Value: []byte(o.Value)}, nil
	default:
		v := strings.TrimPrefix(strings.TrimPrefix(o.Value, "0x"), "0X")
		b, err := hex.DecodeString(v)
		if err != nil {
			return message.Option{}, fmt.Errorf("option %s needs a hex value, got %q", id, o.Value)
		}
		return message.Option{ID: id, Value: b}, nil
	}
}

// OptionOut is an option rendered for a result.
type OptionOut struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value any    `json:"value"`
}

// DescribeOptions renders message options for a result.
func DescribeOptions(opts message.Options) []OptionOut {
	out := make([]OptionOut, 0, len(opts))
	for _, o := range opts {
		oo := OptionOut{ID: int(o.ID), Name: o.ID.String()}
		format := message.ValueOpaque
		if def, ok := message.CoapOptionDefs[o.ID]; ok {
			format = def.ValueFormat
		}
		switch format {
		case message.ValueUint:
			v, _, err := message.DecodeUint32(o.Value)
			if err != nil {
				oo.Value = hex.EncodeToString(o.Value)
			} else if o.ID == message.ContentFormat || o.ID == message.Accept {
				oo.Value = fmt.Sprintf("%d (%s)", v, message.MediaType(v))
			} else {
				oo.Value = v
			}
		case message.ValueString:
			oo.Value = string(o.Value)
		case message.ValueEmpty:
			oo.Value = ""
		default:
			oo.Value = hex.EncodeToString(o.Value)
		}
		out = append(out, oo)
	}
	return out
}

// CodeString renders a CoAP code as "2.05".
func CodeString(c codes.Code) string { return fmt.Sprintf("%d.%02d", uint8(c)>>5, uint8(c)&0x1f) }

// Request is one CoAP request.
type Request struct {
	Method         string // GET, POST, PUT, DELETE, FETCH, PATCH, iPATCH
	Path           string
	Queries        []string
	Options        []Option
	ContentFormat  *message.MediaType
	Accept         *message.MediaType
	Payload        io.ReadSeeker // nil for none
	NonConfirmable bool
	Observe        bool
}

// Response is a decoded CoAP response or notification.
type Response struct {
	Code          codes.Code
	Type          message.Type
	MessageID     int32
	Token         []byte
	Options       message.Options
	ContentFormat *message.MediaType
	Observe       *uint32
	Body          []byte
	Truncated     bool
}

// Conn is a client connection over UDP or TCP.
type Conn interface {
	AcquireMessage(ctx context.Context) *pool.Message
	ReleaseMessage(m *pool.Message)
	Do(req *pool.Message) (*pool.Message, error)
	Close() error
	GetToken() (message.Token, error)
	Done() <-chan struct{}
}

type observer interface {
	DoObserve(req *pool.Message, observeFunc func(req *pool.Message)) (Observation, error)
}

// Observation is an active observe relation.
type Observation interface {
	Cancel(ctx context.Context, opts ...message.Option) error
	Canceled() bool
}

// ConnOptions configures a client connection.
type ConnOptions struct {
	MaxMessageSize uint32
	Timeout        time.Duration
	Errors         func(error)
}

// NewUDP wraps an already dialed (guarded) UDP socket.
func NewUDP(ctx context.Context, c *net.UDPConn, o ConnOptions) Conn {
	opts := []udp.Option{
		options.WithContext(ctx),
		options.WithCloseSocket(),
		options.WithBlockwise(true, blockwise.SZX1024, blockTimeout(o.Timeout)),
	}
	if o.MaxMessageSize > 0 {
		opts = append(opts, options.WithMaxMessageSize(o.MaxMessageSize))
	}
	if o.Errors != nil {
		opts = append(opts, options.WithErrors(o.Errors))
	}
	return &udpConn{udp.Client(c, opts...)}
}

// NewTCP wraps an already dialed (guarded) TCP or TLS connection.
func NewTCP(ctx context.Context, c net.Conn, o ConnOptions) (Conn, error) {
	opts := []tcp.Option{
		options.WithContext(ctx),
		options.WithCloseSocket(),
		options.WithBlockwise(true, blockwise.SZX1024, blockTimeout(o.Timeout)),
	}
	if o.MaxMessageSize > 0 {
		opts = append(opts, options.WithMaxMessageSize(o.MaxMessageSize))
	}
	if o.Errors != nil {
		opts = append(opts, options.WithErrors(o.Errors))
	}
	cc, err := tcp.Client(c, opts...)
	if err != nil {
		return nil, err
	}
	return &tcpConn{cc}, nil
}

func blockTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

type udpConn struct{ *udpclient.Conn }

func (c *udpConn) DoObserve(req *pool.Message, f func(*pool.Message)) (Observation, error) {
	return c.Conn.DoObserve(req, f)
}

type tcpConn struct{ *tcpclient.Conn }

func (c *tcpConn) DoObserve(req *pool.Message, f func(*pool.Message)) (Observation, error) {
	return c.Conn.DoObserve(req, f)
}

func methodCode(m string) (codes.Code, error) {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", "GET":
		return codes.GET, nil
	case "POST":
		return codes.POST, nil
	case "PUT":
		return codes.PUT, nil
	case "DELETE":
		return codes.DELETE, nil
	case "FETCH":
		return codes.FETCH, nil
	case "PATCH":
		return codes.PATCH, nil
	case "IPATCH":
		return codes.IPATCH, nil
	}
	return 0, fmt.Errorf("unsupported CoAP method %q (use GET, POST, PUT, DELETE, FETCH, PATCH or iPATCH)", m)
}

// build creates the request message. The caller must release it.
func build(ctx context.Context, c Conn, r Request) (*pool.Message, error) {
	code, err := methodCode(r.Method)
	if err != nil {
		return nil, err
	}
	if r.Observe && code != codes.GET && code != codes.FETCH {
		return nil, fmt.Errorf("observe requires GET or FETCH")
	}
	token, err := c.GetToken()
	if err != nil {
		return nil, err
	}
	req := c.AcquireMessage(ctx)
	req.SetCode(code)
	req.SetToken(token)
	path := r.Path
	if path == "" {
		path = "/"
	}
	if err := req.SetPath(path); err != nil {
		c.ReleaseMessage(req)
		return nil, fmt.Errorf("path: %w", err)
	}
	for _, q := range r.Queries {
		req.AddQuery(q)
	}
	for _, o := range r.Options {
		opt, err := encodeOption(o)
		if err != nil {
			c.ReleaseMessage(req)
			return nil, err
		}
		req.AddOptionBytes(opt.ID, opt.Value)
	}
	if r.Accept != nil {
		req.SetAccept(*r.Accept)
	}
	if r.Payload != nil {
		cf := message.AppOctets
		if r.ContentFormat != nil {
			cf = *r.ContentFormat
		}
		req.SetContentFormat(cf)
		req.SetBody(r.Payload)
	} else if r.ContentFormat != nil {
		req.SetContentFormat(*r.ContentFormat)
	}
	if r.Observe {
		req.SetObserve(0)
	}
	if r.NonConfirmable {
		req.SetType(message.NonConfirmable)
	}
	return req, nil
}

// Decode converts a pool message, reading at most maxBody bytes of payload.
func Decode(m *pool.Message, maxBody int64) (*Response, error) {
	resp := &Response{Code: m.Code(), Type: m.Type(), MessageID: m.MessageID(), Token: append([]byte(nil), m.Token()...)}
	opts, err := m.Options().Clone()
	if err == nil {
		resp.Options = opts
	}
	if cf, err := m.ContentFormat(); err == nil {
		resp.ContentFormat = &cf
	}
	if obs, err := m.Observe(); err == nil {
		resp.Observe = &obs
	}
	if body := m.Body(); body != nil {
		if _, err := body.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		if maxBody <= 0 {
			maxBody = 1 << 20
		}
		b, err := io.ReadAll(io.LimitReader(body, maxBody+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > maxBody {
			b = b[:maxBody]
			resp.Truncated = true
		}
		resp.Body = b
	}
	return resp, nil
}

// Do sends a request and waits for the response (block-wise transfers are
// reassembled by go-coap).
func Do(ctx context.Context, c Conn, r Request, maxBody int64) (*Response, error) {
	r.Observe = false
	req, err := build(ctx, c, r)
	if err != nil {
		return nil, err
	}
	defer c.ReleaseMessage(req)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer c.ReleaseMessage(resp)
	return Decode(resp, maxBody)
}

// Observe registers an observation (RFC 7641). onNotify receives the first
// response and every notification; it must not block. The returned
// Observation must be cancelled by the caller.
func Observe(ctx context.Context, c Conn, r Request, maxBody int64, onNotify func(*Response, error)) (Observation, error) {
	o, ok := c.(observer)
	if !ok {
		return nil, fmt.Errorf("observe is not supported on this connection")
	}
	r.Observe = true
	req, err := build(ctx, c, r)
	if err != nil {
		return nil, err
	}
	defer c.ReleaseMessage(req)
	return o.DoObserve(req, func(m *pool.Message) {
		resp, err := Decode(m, maxBody)
		onNotify(resp, err)
	})
}

// BytesPayload wraps a byte slice as a payload.
func BytesPayload(b []byte) io.ReadSeeker { return bytes.NewReader(b) }
