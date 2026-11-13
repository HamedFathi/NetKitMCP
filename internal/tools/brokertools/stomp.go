package brokertools

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-stomp/stomp/v3"
	"github.com/go-stomp/stomp/v3/frame"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/stompx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type stompConnIn struct {
	Address          string            `json:"address" jsonschema:"host:port, stomp://host:port or stomp+ssl://host:port (default port 61613, 61614 with TLS)"`
	TLS              bool              `json:"tls,omitempty" jsonschema:"connect with TLS (implied by stomp+ssl:// and by ca_cert, client_cert, server_name, insecure_skip_verify)"`
	Login            string            `json:"login,omitempty" jsonschema:"STOMP login (default: from auth basic)"`
	Passcode         string            `json:"passcode,omitempty" jsonschema:"STOMP passcode (default: from auth basic)"`
	Host             string            `json:"host,omitempty" jsonschema:"CONNECT host header / virtual host (default: the target host; RabbitMQ uses the vhost, e.g. /)"`
	HeartBeatSeconds []float64         `json:"heart_beat_seconds,omitempty" jsonschema:"[send, receive] heart-beat intervals in seconds (default [0, 0] = off)"`
	Versions         []string          `json:"versions,omitempty" jsonschema:"accepted protocol versions: 1.0, 1.1, 1.2 (default all)"`
	ConnectHeaders   map[string]string `json:"connect_headers,omitempty" jsonschema:"extra CONNECT frame headers"`
	types.NetOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"basic (login/passcode) or mtls"`
}

type stompSendIn struct {
	stompConnIn
	Destination string            `json:"destination" jsonschema:"destination, e.g. /queue/orders or /topic/news"`
	Payload     *types.Payload    `json:"payload,omitempty" jsonschema:"message body: text, json, base64 or file"`
	ContentType string            `json:"content_type,omitempty" jsonschema:"content-type header (default: derived from the payload kind)"`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"extra SEND headers (e.g. persistent, priority, expires, reply-to)"`
	Receipt     *bool             `json:"receipt,omitempty" jsonschema:"request a RECEIPT and wait for it (default true)"`
}

type stompSendOut struct {
	Target      string             `json:"target"`
	Destination string             `json:"destination"`
	SizeBytes   int                `json:"size_bytes"`
	File        *types.FileInfo    `json:"file,omitempty"`
	Receipt     bool               `json:"receipt_received"`
	Version     string             `json:"version"`
	Server      string             `json:"server,omitempty"`
	Session     string             `json:"session,omitempty"`
	TLS         *types.TLSInfo     `json:"tls,omitempty"`
	TimingMS    map[string]float64 `json:"timing_ms"`
	Warnings    []string           `json:"warnings,omitempty"`
}

type stompSubscribeIn struct {
	stompConnIn
	Destination string            `json:"destination" jsonschema:"destination to subscribe to"`
	Ack         string            `json:"ack,omitempty" jsonschema:"auto (default), client or client-individual"`
	Settle      string            `json:"settle,omitempty" jsonschema:"with client acks: ack (default), nack, or none (leave unacknowledged so the broker redelivers)"`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"extra SUBSCRIBE headers (e.g. selector, prefetch-count, durable-subscription-name)"`
	Receipt     bool              `json:"receipt,omitempty" jsonschema:"request a RECEIPT for the SUBSCRIBE frame"`
	types.StreamLimits
	MaxResponseBytes int64 `json:"max_response_bytes,omitempty" jsonschema:"maximum total message bytes returned (default 1 MiB)"`
}

func registerSTOMP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "stomp_send", "STOMP send",
		"Send one message to a STOMP 1.0-1.2 broker (ActiveMQ, Artemis, RabbitMQ STOMP plugin): destination, payload (text/json/base64/file), "+
			"content_type and headers. Waits for a RECEIPT by default so delivery to the broker is confirmed.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in stompSendIn) (any, error) {
			return stompSend(ctx, d, in)
		})
	tools.Add(s, d, "stomp_subscribe", "STOMP subscribe",
		"Bounded STOMP subscription: collects up to max_messages within max_duration_seconds (or until idle) from a destination. "+
			"ack: auto (default), client or client-individual; with client acks, settle chooses ack (default), nack or none. Returns body, headers and message-id per message.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in stompSubscribeIn) (any, error) {
			return stompSubscribe(ctx, d, in)
		})
}

type stompSession struct {
	conn     *stompx.Conn
	target   string
	tls      *types.TLSInfo
	warnings []string
	connMS   float64
}

func openSTOMP(ctx context.Context, d *tools.Deps, in stompConnIn, timeout time.Duration) (*stompSession, error) {
	useTLS := in.TLS || wantsTLS(in.TLSOptions, in.Auth)
	t, err := stompx.ParseAddress(in.Address, useTLS)
	if err != nil {
		return nil, err
	}
	o := stompx.Options{Login: in.Login, Passcode: in.Passcode, VHost: in.Host, Versions: in.Versions, Headers: in.ConnectHeaders, Timeout: timeout}
	if o.Login == "" && o.Passcode == "" {
		if o.Login, o.Passcode, err = credentials(in.Auth); err != nil {
			return nil, err
		}
	}
	switch len(in.HeartBeatSeconds) {
	case 0:
	case 2:
		o.HeartBeatSend = time.Duration(in.HeartBeatSeconds[0] * float64(time.Second))
		o.HeartBeatRecv = time.Duration(in.HeartBeatSeconds[1] * float64(time.Second))
	default:
		return nil, fmt.Errorf("heart_beat_seconds must be [send, receive]")
	}
	s := &stompSession{target: t.HostPort}
	var tconf *tls.Config
	if t.TLS {
		if tconf, err = tlsConfig(d, in.TLSOptions, in.Auth, t.Host); err != nil {
			return nil, err
		}
	}
	start := time.Now()
	conn, err := stompx.Dial(ctx, t, d.Guard.Dialer(in.AllowPrivate, timeout), tconf, o)
	if err != nil {
		return nil, err
	}
	s.conn = conn
	s.connMS = ms(start)
	if t.TLS {
		s.tls = tlsInfo(conn.TLS, in.TLSOptions)
		s.warnings = insecureWarnings(in.TLSOptions)
	}
	return s, nil
}

func stompSend(ctx context.Context, d *tools.Deps, in stompSendIn) (any, error) {
	if strings.TrimSpace(in.Destination) == "" {
		return nil, fmt.Errorf("destination is required")
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, ct, file, err := payload(d, in.Payload)
	if err != nil {
		return nil, err
	}
	if in.ContentType != "" {
		ct = in.ContentType
	}
	s, err := openSTOMP(ctx, d, in.stompConnIn, timeout)
	if err != nil {
		return nil, err
	}
	defer s.conn.Close()
	receipt := types.BoolDefault(in.Receipt, true)
	var opts []func(*frame.Frame) error
	if receipt {
		opts = append(opts, stomp.SendOpt.Receipt)
	}
	for k, v := range in.Headers {
		opts = append(opts, stomp.SendOpt.Header(k, v))
	}
	start := time.Now()
	errc := make(chan error, 1)
	go func() { errc <- s.conn.Send(in.Destination, ct, body, opts...) }()
	select {
	case err = <-errc:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if receipt && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, stomp.ErrMsgReceiptTimeout)) {
		return nil, fmt.Errorf("STOMP send: no RECEIPT from %s within %s; delivery is unconfirmed (set receipt=false to skip waiting, or raise timeout_seconds)", s.target, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("STOMP send: %w", err)
	}
	return &stompSendOut{
		Target: s.target, Destination: in.Destination, SizeBytes: len(body), File: file, Receipt: receipt,
		Version: s.conn.Version().String(), Server: s.conn.Server(), Session: s.conn.Session(),
		TLS: s.tls, Warnings: s.warnings,
		TimingMS: map[string]float64{"connect": s.connMS, "send": ms(start), "total": s.connMS + ms(start)},
	}, nil
}

func stompSubscribe(ctx context.Context, d *tools.Deps, in stompSubscribeIn) (any, error) {
	if strings.TrimSpace(in.Destination) == "" {
		return nil, fmt.Errorf("destination is required")
	}
	ackMode, err := stompx.AckMode(in.Ack)
	if err != nil {
		return nil, err
	}
	settle := strings.ToLower(strings.TrimSpace(in.Settle))
	switch settle {
	case "":
		settle = "ack"
	case "ack", "nack", "none":
	default:
		return nil, fmt.Errorf("settle must be ack, nack or none")
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	n, dur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	ctx, cancel := context.WithTimeout(ctx, timeout+dur)
	defer cancel()
	dctx, dcancel := context.WithTimeout(ctx, timeout)
	defer dcancel()
	s, err := openSTOMP(dctx, d, in.stompConnIn, timeout)
	if err != nil {
		return nil, err
	}
	defer s.conn.Close()

	var opts []func(*frame.Frame) error
	for k, v := range in.Headers {
		opts = append(opts, stomp.SubscribeOpt.Header(k, v))
	}
	if in.Receipt {
		opts = append(opts, stomp.SubscribeOpt.Receipt(""))
	}
	sub, err := s.conn.Subscribe(in.Destination, ackMode, opts...)
	if errors.Is(err, stomp.ErrSubscribeReceiptTimeout) {
		return nil, fmt.Errorf("STOMP subscribe: no RECEIPT for SUBSCRIBE from %s within %s (set receipt=false, or raise timeout_seconds)", s.target, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("STOMP subscribe: %w", err)
	}
	coll := types.NewCollector(n, dur, idle, d.Cfg.ResponseBytes(in.MaxResponseBytes))
	var (
		mu       sync.Mutex
		settled  int
		settleEr string
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range sub.C {
			if msg.Err != nil {
				coll.Finish(types.EndedError, msg.Err)
				return
			}
			data, enc, typ := encodeBody(msg.Body, msg.ContentType)
			headers := map[string]string{}
			id := ""
			if msg.Header != nil {
				for i := 0; i < msg.Header.Len(); i++ {
					k, v := msg.Header.GetAt(i)
					if _, dup := headers[k]; !dup {
						headers[k] = v
					}
				}
				id = msg.Header.Get(frame.MessageId)
			}
			m := types.StreamMessage{Dir: "in", Type: typ, Topic: msg.Destination, ID: id, Data: data, Encoding: enc, Headers: headers,
				Meta: map[string]any{"size_bytes": len(msg.Body), "content_type": msg.ContentType}}
			if !coll.Add(m) {
				return
			}
			if msg.ShouldAck() && settle != "none" {
				var err error
				if settle == "nack" {
					err = s.conn.Nack(msg)
				} else {
					err = s.conn.Ack(msg)
				}
				mu.Lock()
				if err != nil && settleEr == "" {
					settleEr = err.Error()
				} else if err == nil {
					settled++
				}
				mu.Unlock()
			}
		}
		coll.Finish(types.EndedPeerClosed, nil)
	}()
	res := coll.Wait(ctx)
	unsub := make(chan struct{})
	go func() {
		sub.Unsubscribe()
		close(unsub)
	}()
	select {
	case <-unsub:
	case <-time.After(2 * time.Second):
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	mu.Lock()
	defer mu.Unlock()
	meta := map[string]any{
		"target":      s.target,
		"destination": in.Destination,
		"ack":         ackMode.String(),
		"version":     s.conn.Version().String(),
	}
	if srv := s.conn.Server(); srv != "" {
		meta["server"] = srv
	}
	if ackMode.ShouldAck() {
		meta["settle"] = settle
		meta["settled"] = settled
	}
	if settleEr != "" {
		meta["settle_error"] = settleEr
	}
	if s.tls != nil {
		meta["tls"] = s.tls
	}
	if len(s.warnings) > 0 {
		meta["warnings"] = s.warnings
	}
	res.Meta = meta
	return res, nil
}
