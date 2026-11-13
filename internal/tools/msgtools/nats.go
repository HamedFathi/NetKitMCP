package msgtools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats.go"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/natsx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupMessaging, registerNATS) }

// NATSConnArgs are the connection arguments shared by the NATS tools.
type NATSConnArgs struct {
	URL               string       `json:"url" jsonschema:"NATS server URL(s), comma-separated: nats://host:4222, tls://host:4222, ws:// or wss://; bare host:port means nats://"`
	Username          string       `json:"username,omitempty" jsonschema:"user name (overrides auth)"`
	Password          string       `json:"password,omitempty" jsonschema:"password (overrides auth)"`
	Token             string       `json:"token,omitempty" jsonschema:"authentication token (overrides auth bearer)"`
	NKeySeed          string       `json:"nkey_seed,omitempty" jsonschema:"NKey user seed (SU...) inline, or a file path in an allowed read directory"`
	Creds             string       `json:"creds,omitempty" jsonschema:"NATS .creds (user JWT + seed) inline, or a file path in an allowed read directory"`
	TLSHandshakeFirst bool         `json:"tls_handshake_first,omitempty" jsonschema:"perform the TLS handshake before the NATS INFO exchange"`
	Auth              *auth.Config `json:"auth,omitempty" jsonschema:"auth object: basic (user/password), bearer (token) or mtls"`
	types.NetOptions
}

type natsConnInfo struct {
	Server        string         `json:"server"`
	ServerID      string         `json:"server_id,omitempty"`
	ServerName    string         `json:"server_name,omitempty"`
	ServerVersion string         `json:"server_version,omitempty"`
	TLS           *types.TLSInfo `json:"tls,omitempty"`
}

type natsConn struct {
	nc       *nats.Conn
	info     natsConnInfo
	warnings []string
	connect  time.Duration
}

func loadSecret(d *tools.Deps, v string, inline func(string) bool) (string, error) {
	v = strings.TrimSpace(v)
	if inline(v) {
		return v, nil
	}
	b, err := d.Files.ReadSmall(v, 64<<10)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (a *NATSConnArgs) connect(ctx context.Context, d *tools.Deps, onAsync func(error), onDisconnect func(error)) (*natsConn, error) {
	servers, err := natsx.NormalizeServers(a.URL)
	if err != nil {
		return nil, err
	}
	timeout := d.Cfg.Timeout(a.TimeoutSeconds)
	cfg := natsx.Config{
		Servers:      servers,
		Dialer:       d.Guard.Dialer(a.AllowPrivate, timeout),
		Name:         "netkit-mcp",
		Timeout:      timeout,
		TLSFirst:     a.TLSHandshakeFirst,
		OnAsyncError: onAsync,
		OnDisconnect: onDisconnect,
	}
	if a.Auth != nil {
		switch k := a.Auth.Kind(); k {
		case "none":
		case "mtls":
			auth.ApplyTLS(a.Auth, &a.TLSOptions)
		case "bearer":
			cfg.Token = a.Auth.Token
		default:
			u, p, ok := auth.UserPass(a.Auth)
			if !ok {
				return nil, fmt.Errorf("auth type %q is not supported for NATS; use basic, bearer (token), mtls, or the username/password/token/nkey_seed/creds arguments", k)
			}
			cfg.User, cfg.Password = u, p
		}
	}
	if a.Username != "" || a.Password != "" {
		cfg.User, cfg.Password = a.Username, a.Password
	}
	if a.Token != "" {
		cfg.Token = a.Token
	}
	if a.NKeySeed != "" {
		seed, err := loadSecret(d, a.NKeySeed, func(s string) bool { return strings.HasPrefix(s, "SU") && !strings.ContainsAny(s, "/\\") })
		if err != nil {
			return nil, fmt.Errorf("nkey_seed: %w", err)
		}
		cfg.NKeySeed = seed
	}
	if a.Creds != "" {
		c, err := loadSecret(d, a.Creds, func(s string) bool { return strings.Contains(s, "-----BEGIN") })
		if err != nil {
			return nil, fmt.Errorf("creds: %w", err)
		}
		if cfg.JWT, cfg.JWTSeed, err = natsx.ParseCreds([]byte(c)); err != nil {
			return nil, err
		}
	}
	useTLS := a.CACert != "" || a.ClientCert != "" || a.InsecureSkipVerify || a.ServerName != "" || a.TLSHandshakeFirst
	for _, s := range servers {
		if strings.HasPrefix(s, "tls://") || strings.HasPrefix(s, "wss://") {
			useTLS = true
		}
	}
	nw := &natsConn{}
	if useTLS {
		tc, err := tlsx.Config(d.Files, a.TLSOptions, "", nil)
		if err != nil {
			return nil, err
		}
		cfg.TLS = tc
		nw.warnings = insecureWarning(a.TLSOptions, true)
	}
	start := time.Now()
	type result struct {
		nc  *nats.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		nc, err := natsx.Connect(cfg)
		ch <- result{nc, err}
	}()
	var r result
	select {
	case r = <-ch:
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.nc != nil {
				r.nc.Close()
			}
		}()
		return nil, fmt.Errorf("NATS connect: %w", ctx.Err())
	}
	if r.err != nil {
		return nil, r.err
	}
	nw.nc = r.nc
	nw.connect = time.Since(start)
	nw.info = natsConnInfo{
		Server:        redact.URL(r.nc.ConnectedUrlRedacted()),
		ServerID:      r.nc.ConnectedServerId(),
		ServerName:    r.nc.ConnectedServerName(),
		ServerVersion: r.nc.ConnectedServerVersion(),
	}
	if cs, err := r.nc.TLSConnectionState(); err == nil {
		nw.info.TLS = tlsx.Info(&cs, a.InsecureSkipVerify)
	}
	return nw, nil
}

func natsErr(subject string, err error, timeout time.Duration) error {
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		return fmt.Errorf("no responders: nothing is subscribed to %q (request/reply needs a service listening on the subject)", subject)
	case errors.Is(err, nats.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("no reply on %q within %s (raise timeout_seconds)", subject, timeout)
	}
	return err
}

// NATSPublishArgs are the nats_publish arguments.
type NATSPublishArgs struct {
	NATSConnArgs
	Subject string            `json:"subject" jsonschema:"subject to publish to (no wildcards)"`
	Payload *types.Payload    `json:"payload,omitempty" jsonschema:"payload: text, json, base64 or file (omit for empty)"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"NATS message headers (requires server 2.2+)"`
	ReplyTo string            `json:"reply_to,omitempty" jsonschema:"reply subject to attach to the message"`
}

type natsSent struct {
	Subject     string            `json:"subject"`
	ReplyTo     string            `json:"reply_to,omitempty"`
	Bytes       int               `json:"bytes"`
	Headers     map[string]string `json:"headers,omitempty"`
	PayloadFile *types.FileInfo   `json:"payload_file,omitempty"`
}

type natsPublishOut struct {
	natsConnInfo
	Published natsSent `json:"published"`
	Flushed   bool     `json:"flushed"`
	TimingMS  timingMS `json:"timing_ms"`
	Warnings  []string `json:"warnings,omitempty"`
}

func buildNATSMsg(d *tools.Deps, nc *nats.Conn, subject, reply string, p *types.Payload, headers map[string]string) (*nats.Msg, natsSent, error) {
	if err := natsx.ValidateSubject(subject, false); err != nil {
		return nil, natsSent{}, err
	}
	max := int64(1 << 20)
	if nc != nil && nc.MaxPayload() > 0 {
		max = nc.MaxPayload()
	}
	pd, err := resolvePayload(d, p, max)
	if err != nil {
		return nil, natsSent{}, err
	}
	m := &nats.Msg{Subject: subject, Reply: reply, Data: pd.Data, Header: natsx.Headers(headers)}
	return m, natsSent{Subject: subject, ReplyTo: reply, Bytes: len(pd.Data), Headers: redact.Map(headers), PayloadFile: pd.File}, nil
}

func publishNATS(ctx context.Context, d *tools.Deps, in NATSPublishArgs) (any, error) {
	start := time.Now()
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := natsx.ValidateSubject(in.Subject, false); err != nil {
		return nil, err
	}
	c, err := in.connect(ctx, d, nil, nil)
	if err != nil {
		return nil, err
	}
	defer c.nc.Close()
	m, sent, err := buildNATSMsg(d, c.nc, in.Subject, in.ReplyTo, in.Payload, in.Headers)
	if err != nil {
		return nil, err
	}
	opStart := time.Now()
	if err := c.nc.PublishMsg(m); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}
	if err := c.nc.FlushWithContext(ctx); err != nil {
		return nil, fmt.Errorf("flush: %w", err)
	}
	out := natsPublishOut{natsConnInfo: c.info, Published: sent, Flushed: true, Warnings: c.warnings}
	out.TimingMS.Connect = types.MS(c.connect)
	out.TimingMS.Op = types.MS(time.Since(opStart))
	out.TimingMS.Total = types.MS(time.Since(start))
	return out, nil
}

// NATSRequestArgs are the nats_request arguments.
type NATSRequestArgs struct {
	NATSPublishArgs
}

type natsReply struct {
	Subject   string            `json:"subject"`
	Data      string            `json:"data"`
	Encoding  string            `json:"encoding"`
	Headers   map[string]string `json:"headers,omitempty"`
	SizeBytes int               `json:"size_bytes"`
	Truncated bool              `json:"truncated"`
}

type natsRequestOut struct {
	natsConnInfo
	Request  natsSent  `json:"request"`
	Reply    natsReply `json:"reply"`
	TimingMS timingMS  `json:"timing_ms"`
	Warnings []string  `json:"warnings,omitempty"`
}

func requestNATS(ctx context.Context, d *tools.Deps, in NATSRequestArgs) (any, error) {
	start := time.Now()
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := natsx.ValidateSubject(in.Subject, false); err != nil {
		return nil, err
	}
	if in.ReplyTo != "" {
		return nil, fmt.Errorf("reply_to is chosen automatically by nats_request; use nats_publish to set it")
	}
	c, err := in.connect(ctx, d, nil, nil)
	if err != nil {
		return nil, err
	}
	defer c.nc.Close()
	m, sent, err := buildNATSMsg(d, c.nc, in.Subject, "", in.Payload, in.Headers)
	if err != nil {
		return nil, err
	}
	opStart := time.Now()
	reply, err := c.nc.RequestMsgWithContext(ctx, m)
	if err != nil {
		return nil, natsErr(in.Subject, err, timeout)
	}
	maxBytes := d.Cfg.ResponseBytes(0)
	data := reply.Data
	truncated := false
	if int64(len(data)) > maxBytes {
		data, truncated = data[:maxBytes], true
	}
	body, enc := types.EncodeBody(data, reply.Header.Get("Content-Type"))
	out := natsRequestOut{
		natsConnInfo: c.info,
		Request:      sent,
		Reply: natsReply{Subject: reply.Subject, Data: body, Encoding: enc, Headers: natsx.FlattenHeaders(reply.Header),
			SizeBytes: len(reply.Data), Truncated: truncated},
		Warnings: c.warnings,
	}
	out.TimingMS.Connect = types.MS(c.connect)
	out.TimingMS.Op = types.MS(time.Since(opStart))
	out.TimingMS.Total = types.MS(time.Since(start))
	return out, nil
}

// NATSPublishFirst is a message published after subscribing.
type NATSPublishFirst struct {
	Subject string            `json:"subject" jsonschema:"subject to publish to"`
	Payload *types.Payload    `json:"payload,omitempty" jsonschema:"payload: text, json, base64 or file"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"message headers"`
	ReplyTo string            `json:"reply_to,omitempty" jsonschema:"reply subject (subscribe to it as well to capture replies)"`
}

// NATSSubscribeArgs are the nats_subscribe arguments.
type NATSSubscribeArgs struct {
	NATSConnArgs
	Subject      string            `json:"subject,omitempty" jsonschema:"subject to subscribe to; wildcards * (one token) and > (rest)"`
	Subjects     []string          `json:"subjects,omitempty" jsonschema:"several subjects"`
	Queue        string            `json:"queue,omitempty" jsonschema:"queue group name (messages are load-balanced across members)"`
	PublishFirst *NATSPublishFirst `json:"publish_first,omitempty" jsonschema:"publish this message after subscribing (request/response testing)"`
	types.StreamLimits
}

func natsStreamMessage(m *nats.Msg) types.StreamMessage {
	data, enc := types.EncodeBody(m.Data, m.Header.Get("Content-Type"))
	meta := map[string]any{"size_bytes": len(m.Data)}
	if m.Reply != "" {
		meta["reply"] = m.Reply
	}
	if m.Sub != nil {
		meta["subscription"] = m.Sub.Subject
	}
	return types.StreamMessage{Dir: "in", Type: "message", Topic: m.Subject, Data: data, Encoding: enc,
		Headers: natsx.FlattenHeaders(m.Header), Meta: meta}
}

func subscribeNATS(ctx context.Context, d *tools.Deps, in NATSSubscribeArgs) (any, error) {
	subjects := append([]string(nil), in.Subjects...)
	if in.Subject != "" {
		subjects = append([]string{in.Subject}, subjects...)
	}
	if len(subjects) == 0 {
		return nil, fmt.Errorf("set subject or subjects (e.g. orders.> or sensors.*.temp)")
	}
	for _, s := range subjects {
		if err := natsx.ValidateSubject(s, true); err != nil {
			return nil, err
		}
	}
	if in.PublishFirst != nil {
		if err := natsx.ValidateSubject(in.PublishFirst.Subject, false); err != nil {
			return nil, fmt.Errorf("publish_first: %w", err)
		}
	}
	n, dur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	col := types.NewCollector(n, dur, idle, 0)
	var asyncErrs []string
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	asyncCh := make(chan string, 16)
	c, err := in.connect(cctx, d, func(err error) {
		select {
		case asyncCh <- err.Error():
		default:
		}
	}, func(err error) {
		if err == nil {
			err = errors.New("connection closed")
		}
		col.Finish(types.EndedPeerClosed, err)
	})
	if err != nil {
		return nil, err
	}
	defer c.nc.Close()
	handler := func(m *nats.Msg) { col.Add(natsStreamMessage(m)) }
	for _, s := range subjects {
		var err error
		if in.Queue != "" {
			_, err = c.nc.QueueSubscribe(s, in.Queue, handler)
		} else {
			_, err = c.nc.Subscribe(s, handler)
		}
		if err != nil {
			return nil, fmt.Errorf("subscribe %q: %w", s, err)
		}
	}
	if err := c.nc.FlushWithContext(cctx); err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	if err := c.nc.LastError(); err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	meta := map[string]any{"connection": c.info, "subjects": subjects}
	if in.Queue != "" {
		meta["queue"] = in.Queue
	}
	if pf := in.PublishFirst; pf != nil {
		m, sent, err := buildNATSMsg(d, c.nc, pf.Subject, pf.ReplyTo, pf.Payload, pf.Headers)
		if err != nil {
			return nil, fmt.Errorf("publish_first: %w", err)
		}
		data, enc := types.EncodeBody(m.Data, "")
		col.Add(types.StreamMessage{Dir: "out", Type: "message", Topic: m.Subject, Data: data, Encoding: enc, Headers: redact.Map(pf.Headers)})
		if err := c.nc.PublishMsg(m); err != nil {
			return nil, fmt.Errorf("publish_first: %w", err)
		}
		meta["published"] = sent
	}
	res := col.Wait(ctx)
drain:
	for {
		select {
		case e := <-asyncCh:
			asyncErrs = append(asyncErrs, e)
		default:
			break drain
		}
	}
	warnings := c.warnings
	if len(asyncErrs) > 0 {
		warnings = append(warnings, asyncErrs...)
	}
	if len(warnings) > 0 {
		meta["warnings"] = warnings
	}
	res.Meta = meta
	return res, nil
}

func registerNATS(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "nats_publish", "NATS publish",
		"Publish one message to a core NATS subject (with optional headers and reply subject) and flush it to the server. "+
			"Auth: username/password, token, NKey seed, .creds, or the auth object; TLS/mTLS via tls:// or TLS options. JetStream is not supported yet (core NATS only).",
		tools.Mutating, func(ctx context.Context, _ *mcp.CallToolRequest, in NATSPublishArgs) (any, error) {
			return publishNATS(ctx, d, in)
		})
	tools.Add(s, d, "nats_request", "NATS request/reply",
		"Send a core NATS request and wait for the first reply (timeout_seconds, default 30). Returns the reply data (text or base64) and headers; "+
			"reports 'no responders' when nothing listens on the subject. JetStream is not supported yet.",
		tools.Mutating, func(ctx context.Context, _ *mcp.CallToolRequest, in NATSRequestArgs) (any, error) {
			return requestNATS(ctx, d, in)
		})
	tools.Add(s, d, "nats_subscribe", "NATS subscribe",
		"Subscribe to core NATS subjects (wildcards * and >, optional queue group) and collect messages until max_messages, max_duration_seconds (default 10) "+
			"or idle_timeout_seconds. publish_first sends a message after subscribing. Returns subject, data, headers and reply subject per message. JetStream is not supported yet.",
		tools.ReadOnly, func(ctx context.Context, _ *mcp.CallToolRequest, in NATSSubscribeArgs) (any, error) {
			return subscribeNATS(ctx, d, in)
		})
}
