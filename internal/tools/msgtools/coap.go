package msgtools

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/plgd-dev/go-coap/v3/message"

	"github.com/HamedFathi/NetKitMCP/internal/coapx"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupMessaging, registerCoAP) }

// CoAPOption is a request option.
type CoAPOption struct {
	Name  string `json:"name" jsonschema:"option name or number: uri-query, accept, etag, if-match, if-none-match, max-age, uri-host, proxy-uri, ..."`
	Value string `json:"value,omitempty" jsonschema:"value: decimal for integer options, hex for opaque options (etag, if-match), text otherwise"`
}

// CoAPArgs are the coap_request arguments.
type CoAPArgs struct {
	URL              string         `json:"url" jsonschema:"coap://host[:5683]/path?query (UDP), coap+tcp:// (TCP) or coaps+tcp:// (TLS); coaps:// (DTLS) is not supported"`
	Method           string         `json:"method,omitempty" jsonschema:"GET (default), POST, PUT, DELETE, FETCH, PATCH or iPATCH"`
	Payload          *types.Payload `json:"payload,omitempty" jsonschema:"request payload: text, json, base64 or file (large payloads use block-wise transfer)"`
	ContentFormat    string         `json:"content_format,omitempty" jsonschema:"payload content format: number or name (text/plain, application/json, application/cbor, application/octet-stream, ...); default from the payload"`
	Accept           string         `json:"accept,omitempty" jsonschema:"Accept option: number or content format name"`
	Query            []string       `json:"query,omitempty" jsonschema:"extra Uri-Query values (key=value)"`
	Options          []CoAPOption   `json:"options,omitempty" jsonschema:"extra CoAP options"`
	Confirmable      *bool          `json:"confirmable,omitempty" jsonschema:"send as Confirmable with retransmission (default true; UDP only)"`
	Observe          bool           `json:"observe,omitempty" jsonschema:"register an observation (GET) and collect notifications"`
	MaxNotifications int            `json:"max_notifications,omitempty" jsonschema:"observe: stop after this many notifications (default 100)"`
	MaxDuration      float64        `json:"max_duration_seconds,omitempty" jsonschema:"observe: stop after this many seconds (default 10)"`
	IdleTimeout      float64        `json:"idle_timeout_seconds,omitempty" jsonschema:"observe: stop when no notification arrives for this many seconds"`
	MaxResponseBytes int64          `json:"max_response_bytes,omitempty" jsonschema:"maximum response payload bytes (default 1 MiB)"`
	types.NetOptions
}

type coapResponseOut struct {
	Code          string            `json:"code"`
	CodeName      string            `json:"code_name"`
	Success       bool              `json:"success"`
	Type          string            `json:"type,omitempty"`
	MessageID     int32             `json:"message_id,omitempty"`
	Token         string            `json:"token,omitempty"`
	ContentFormat string            `json:"content_format,omitempty"`
	Options       []coapx.OptionOut `json:"options"`
	Body          string            `json:"body"`
	BodyEncoding  string            `json:"body_encoding"`
	SizeBytes     int               `json:"size_bytes"`
	Truncated     bool              `json:"truncated"`
	Request       map[string]any    `json:"request"`
	TLS           *types.TLSInfo    `json:"tls,omitempty"`
	TimingMS      struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Warnings []string `json:"warnings,omitempty"`
}

func coapBody(r *coapx.Response) (string, string, string) {
	ct := ""
	if r.ContentFormat != nil {
		ct = r.ContentFormat.String()
	}
	mimeHint := ct
	if strings.HasPrefix(mimeHint, "MediaType(") {
		mimeHint = ""
	}
	body, enc := types.EncodeBody(r.Body, mimeHint)
	return body, enc, ct
}

func defaultContentFormat(pd *payloadData, p *types.Payload) message.MediaType {
	ct := strings.ToLower(pd.ContentType)
	switch {
	case p != nil && p.JSON != nil, strings.Contains(ct, "json"):
		return message.AppJSON
	case p != nil && p.Text != nil, strings.HasPrefix(ct, "text/"):
		return message.TextPlain
	case strings.Contains(ct, "xml"):
		return message.AppXML
	case strings.Contains(ct, "cbor"):
		return message.AppCBOR
	}
	return message.AppOctets
}

func coapRequest(ctx context.Context, d *tools.Deps, in CoAPArgs) (any, error) {
	start := time.Now()
	t, err := coapx.ParseURL(in.URL)
	if err != nil {
		return nil, err
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	maxBody := d.Cfg.ResponseBytes(in.MaxResponseBytes)

	req := coapx.Request{Method: in.Method, Path: t.Path, Queries: append(t.Queries, in.Query...)}
	for _, o := range in.Options {
		req.Options = append(req.Options, coapx.Option{Name: o.Name, Value: o.Value})
	}
	var warnings []string
	if in.Confirmable != nil && !*in.Confirmable {
		if t.Network == "udp" {
			req.NonConfirmable = true
		} else {
			warnings = append(warnings, "confirmable=false only applies to UDP; ignored")
		}
	}
	if in.Accept != "" {
		mt, err := coapx.ParseMediaType(in.Accept)
		if err != nil {
			return nil, fmt.Errorf("accept: %w", err)
		}
		req.Accept = &mt
	}
	var cf *message.MediaType
	if in.ContentFormat != "" {
		mt, err := coapx.ParseMediaType(in.ContentFormat)
		if err != nil {
			return nil, fmt.Errorf("content_format: %w", err)
		}
		cf = &mt
	}
	reqEcho := map[string]any{"method": strings.ToUpper(firstNonEmpty(in.Method, "GET")), "url": t.URL.String()}
	payloadSize := int64(0)
	if in.Payload != nil && !in.Payload.IsZero() {
		limit := d.Cfg.UploadBytes(0)
		rp, err := in.Payload.Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, limit)
		if err != nil {
			return nil, err
		}
		defer rp.Close()
		pd := &payloadData{ContentType: rp.ContentType}
		if rs, ok := rp.Reader.(io.ReadSeeker); ok && rp.Reader != nil {
			req.Payload = rs // streamed block-wise from the file
			reqEcho["payload_file"] = rp.File
		} else {
			if pd.Data, err = rp.Bytes(limit); err != nil {
				return nil, err
			}
			req.Payload = bytes.NewReader(pd.Data)
		}
		payloadSize = rp.Size
		if cf == nil {
			mt := defaultContentFormat(pd, in.Payload)
			cf = &mt
		}
		reqEcho["payload_bytes"] = rp.Size
	}
	req.ContentFormat = cf
	if cf != nil {
		reqEcho["content_format"] = cf.String()
	}

	// Dial through the SSRF guard. UDP: CheckAddress, then the guarded
	// net.Dialer (its Control re-checks the resolved IP for UDP as well).
	dialer := d.Guard.Dialer(in.AllowPrivate, timeout)
	if err := dialer.CheckAddress(t.Host); err != nil {
		return nil, err
	}
	dur := time.Duration(0)
	if in.Observe {
		lim := types.StreamLimits{MaxMessages: in.MaxNotifications, MaxDurationSeconds: in.MaxDuration, IdleTimeoutSeconds: in.IdleTimeout}
		_, dur, _ = lim.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+dur)
	defer cancel()
	maxMsg := maxBody
	if payloadSize > maxMsg {
		maxMsg = payloadSize
	}
	if maxMsg < 64<<10 {
		maxMsg = 64 << 10
	}
	if maxMsg > 1<<31 {
		maxMsg = 1 << 31
	}
	copts := coapx.ConnOptions{MaxMessageSize: uint32(maxMsg) + 1024, Timeout: timeout}
	var conn coapx.Conn
	var tlsInfo *types.TLSInfo
	nd := dialer.NetDialer()
	switch {
	case t.Network == "udp":
		c, err := nd.DialContext(cctx, "udp", t.Host)
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UDPConn)
		if !ok {
			c.Close()
			return nil, fmt.Errorf("unexpected UDP connection type %T", c)
		}
		conn = coapx.NewUDP(cctx, uc, copts)
	default:
		c, err := nd.DialContext(cctx, "tcp", t.Host)
		if err != nil {
			return nil, err
		}
		if t.TLS {
			tc, err := tlsx.Config(d.Files, in.TLSOptions, t.URL.Hostname(), []string{"coap"})
			if err != nil {
				c.Close()
				return nil, err
			}
			tconn := tls.Client(c, tc)
			if err := tconn.HandshakeContext(cctx); err != nil {
				c.Close()
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			st := tconn.ConnectionState()
			tlsInfo = tlsx.Info(&st, in.InsecureSkipVerify)
			warnings = append(warnings, insecureWarning(in.TLSOptions, true)...)
			c = tconn
		}
		conn, err = coapx.NewTCP(cctx, c, copts)
		if err != nil {
			c.Close()
			return nil, err
		}
	}
	defer conn.Close()

	if !in.Observe {
		rctx, rcancel := context.WithTimeout(cctx, timeout)
		defer rcancel()
		resp, err := coapx.Do(rctx, conn, req, maxBody)
		if err != nil {
			if rctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("no CoAP response from %s within %s (is a CoAP server listening? raise timeout_seconds)", t.Host, timeout)
			}
			return nil, fmt.Errorf("CoAP request: %w", err)
		}
		body, enc, ct := coapBody(resp)
		out := coapResponseOut{
			Code:          coapx.CodeString(resp.Code),
			CodeName:      resp.Code.String(),
			Success:       uint8(resp.Code)>>5 == 2,
			MessageID:     resp.MessageID,
			Token:         hex.EncodeToString(resp.Token),
			ContentFormat: ct,
			Options:       coapx.DescribeOptions(resp.Options),
			Body:          body,
			BodyEncoding:  enc,
			SizeBytes:     len(resp.Body),
			Truncated:     resp.Truncated,
			Request:       reqEcho,
			TLS:           tlsInfo,
			Warnings:      warnings,
		}
		if t.Network == "udp" {
			out.Type = resp.Type.String()
		}
		out.TimingMS.Total = types.MS(time.Since(start))
		return out, nil
	}

	lim := types.StreamLimits{MaxMessages: in.MaxNotifications, MaxDurationSeconds: in.MaxDuration, IdleTimeoutSeconds: in.IdleTimeout}
	n, dur, idle := lim.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	col := types.NewCollector(n, dur, idle, 0)
	var mu sync.Mutex
	first := true
	var firstCode string
	notify := func(r *coapx.Response, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			col.Finish(types.EndedError, err)
			return
		}
		body, enc, ct := coapBody(r)
		meta := map[string]any{"code": coapx.CodeString(r.Code), "code_name": r.Code.String(), "size_bytes": len(r.Body)}
		if ct != "" {
			meta["content_format"] = ct
		}
		if r.Observe != nil {
			meta["observe"] = *r.Observe
		}
		if r.Truncated {
			meta["truncated"] = true
		}
		col.Add(types.StreamMessage{Dir: "in", Type: "notification", Data: body, Encoding: enc, Meta: meta})
		if first {
			first = false
			firstCode = coapx.CodeString(r.Code)
			if r.Observe == nil {
				col.Finish(types.EndedComplete, nil)
			}
		}
	}
	octx, ocancel := context.WithTimeout(cctx, timeout)
	obs, err := coapx.Observe(octx, conn, req, maxBody, notify)
	ocancel()
	if err != nil {
		return nil, fmt.Errorf("CoAP observe: %w", err)
	}
	res := col.Wait(cctx)
	cctx2, c2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = obs.Cancel(cctx2)
	c2()
	meta := map[string]any{"request": reqEcho, "timing_ms": map[string]float64{"total": types.MS(time.Since(start))}}
	mu.Lock()
	if firstCode != "" {
		meta["first_code"] = firstCode
	}
	mu.Unlock()
	if res.EndedBy == types.EndedComplete {
		warnings = append(warnings, "the server answered without an Observe option, so the resource is not observable; only the first response was collected")
	}
	if tlsInfo != nil {
		meta["tls"] = tlsInfo
	}
	if len(warnings) > 0 {
		meta["warnings"] = warnings
	}
	res.Meta = meta
	return res, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func registerCoAP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "coap_request", "CoAP request",
		"Send a CoAP request (GET/POST/PUT/DELETE/FETCH/PATCH) over UDP (coap://), TCP (coap+tcp://) or TLS (coaps+tcp://); DTLS is not supported. "+
			"Confirmable by default, content_format/accept by name or number, extra options (uri-query, etag, ...), payload as text/JSON/base64/file with block-wise transfer. "+
			"Returns the response code (e.g. 2.05 Content), options and payload. observe=true registers an observation and collects notifications until max_notifications or max_duration_seconds.",
		tools.Mutating, func(ctx context.Context, _ *mcp.CallToolRequest, in CoAPArgs) (any, error) {
			return coapRequest(ctx, d, in)
		})
}
