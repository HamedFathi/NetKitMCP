package wstools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/sio"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// sioTarget identifies a Socket.IO endpoint.
type sioTarget struct {
	URL       string            `json:"url" jsonschema:"server URL (http, https, ws or wss); a path other than the endpoint path is used as the namespace, like the JS client"`
	Path      string            `json:"path,omitempty" jsonschema:"Engine.IO endpoint path (default /socket.io/)"`
	Query     map[string]string `json:"query,omitempty" jsonschema:"extra handshake query parameters"`
	Transport string            `json:"transport,omitempty" jsonschema:"websocket (default) or polling (HTTP long-polling)"`
	Upgrade   *bool             `json:"upgrade,omitempty" jsonschema:"with transport=polling: upgrade to websocket when offered (default true)"`
	connOptions
}

// sioEvent is one event to emit.
type sioEvent struct {
	Event       string          `json:"event" jsonschema:"event name"`
	Args        []any           `json:"args,omitempty" jsonschema:"event arguments (JSON values)"`
	Attachments []types.Payload `json:"attachments,omitempty" jsonschema:"binary attachments (base64 or file); sent as BINARY_EVENT and appended after args as placeholders unless args already contain {\"_placeholder\":true,\"num\":N}"`
	Ack         bool            `json:"ack,omitempty" jsonschema:"request an acknowledgement (it is collected with type ack and meta.ack_id)"`
	Namespace   string          `json:"namespace,omitempty" jsonschema:"namespace (default: the tool's namespace)"`
	DelayMS     int             `json:"delay_ms,omitempty" jsonschema:"wait this many milliseconds before emitting"`
}

type sioExchangeIn struct {
	sioTarget
	Namespace   string     `json:"namespace,omitempty" jsonschema:"namespace to join (default /)"`
	AuthPayload any        `json:"auth_payload,omitempty" jsonschema:"Socket.IO CONNECT auth payload (JSON object), e.g. {\"token\":\"...\"}"`
	Events      []sioEvent `json:"events,omitempty" jsonschema:"events to emit in order after joining"`
	Listen      []string   `json:"listen,omitempty" jsonschema:"only collect these incoming event names (acks are always collected)"`
	AutoAck     bool       `json:"auto_ack,omitempty" jsonschema:"answer server ack requests automatically with auto_ack_args"`
	AutoAckArgs []any      `json:"auto_ack_args,omitempty" jsonschema:"arguments for automatic acks (default none)"`
	StopOnEvent string     `json:"stop_on_event,omitempty" jsonschema:"stop collecting when this event name arrives"`
	types.StreamLimits
}

// resolve builds the Engine.IO URL and the namespace implied by the URL path.
func (t sioTarget) resolve() (endpoint, urlNamespace string, err error) {
	u, err := url.Parse(strings.TrimSpace(t.URL))
	if err != nil {
		return "", "", fmt.Errorf("invalid url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ws", "wss":
	default:
		return "", "", fmt.Errorf("unsupported URL scheme %q (use http, https, ws or wss)", u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("url %q has no host", t.URL)
	}
	path := t.Path
	if path == "" {
		path = "/socket.io/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	switch p := u.Path; {
	case p == "" || p == "/":
	case strings.TrimSuffix(p, "/") == strings.TrimSuffix(path, "/"):
		path = p
	default:
		urlNamespace = p
	}
	u.Path = path
	u.RawPath = ""
	q := u.Query()
	for k, v := range t.Query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), urlNamespace, nil
}

// dial opens the Engine.IO connection through the guarded client.
func (t sioTarget) dial(ctx context.Context, d *tools.Deps, onMessage func(sio.Message)) (*sio.Client, *httpx.Client, error) {
	endpoint, _, err := t.resolve()
	if err != nil {
		return nil, nil, err
	}
	transport := strings.ToLower(t.Transport)
	if transport == "" {
		transport = sio.TransportWebSocket
	}
	if transport != sio.TransportWebSocket && transport != sio.TransportPolling {
		return nil, nil, fmt.Errorf("transport must be websocket or polling, got %q", t.Transport)
	}
	// Long-polling GETs are held open for up to pingInterval (25s by
	// default), so the transport's response-header timeout must exceed it.
	var minTimeout time.Duration
	if transport == sio.TransportPolling {
		minTimeout = 60 * time.Second
	}
	hc, err := newClient(d, t.connOptions, minTimeout)
	if err != nil {
		return nil, nil, err
	}
	jar, _ := cookiejar.New(nil)
	hc.Client.Jar = jar
	dctx, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(t.TimeoutSeconds))
	defer cancel()
	c, err := sio.Dial(dctx, sio.Config{
		Engine: sio.EngineConfig{
			URL:         endpoint,
			HTTPClient:  hc.Client,
			Header:      tools.Headers(t.Headers),
			Origin:      t.Origin,
			Transport:   transport,
			Upgrade:     types.BoolDefault(t.Upgrade, true),
			Compression: t.Compression,
			ReadLimit:   d.Cfg.ResponseBytes(t.MaxMessageBytes),
		},
		OnMessage: onMessage,
	})
	if err != nil {
		hc.Close()
		return nil, nil, err
	}
	return c, hc, nil
}

// connectTimeout bounds namespace joins and acks.
func (t sioTarget) connectTimeout(d *tools.Deps) time.Duration {
	return d.Cfg.Timeout(t.TimeoutSeconds)
}

func engineInfo(c *sio.Client) map[string]any {
	e := c.Engine()
	m := map[string]any{
		"sid":       e.HS.SID,
		"transport": e.Transport(),
		"handshake": map[string]any{
			"ping_interval_ms": e.HS.PingInterval,
			"ping_timeout_ms":  e.HS.PingTimeout,
			"max_payload":      e.HS.MaxPayload,
			"upgrades":         e.HS.Upgrades,
		},
		"namespaces": c.Namespaces(),
	}
	if e.Upgraded() {
		m["upgraded_from"] = sio.TransportPolling
	}
	if n := e.PingsAnswered(); n > 0 {
		m["pings_answered"] = n
	}
	if e.RespHeads != nil {
		m["response_headers"] = redact.Headers(e.RespHeads)
	}
	return m
}

// sioMessage converts a received Socket.IO message into a stream message.
func sioMessage(m sio.Message) types.StreamMessage {
	sm := types.StreamMessage{Dir: "in", Type: m.Kind, Event: m.Event, Data: string(m.Data), Encoding: "text",
		Meta: map[string]any{}}
	if m.Namespace != "" {
		sm.Meta["namespace"] = m.Namespace
	}
	if m.AckID != nil {
		sm.Meta["ack_id"] = *m.AckID
		if m.Kind == sio.KindEvent {
			sm.Meta["ack_requested"] = true
		}
	}
	if m.Attachments > 0 {
		sm.Meta["attachments"] = m.Attachments
	}
	if m.Err != "" {
		sm.Data = m.Err
	}
	return sm
}

// outMessage records an emitted event or ack.
func outMessage(kind string, em *sio.Packet, event string, ackID *int64) types.StreamMessage {
	data := em.Data
	if event != "" {
		var arr []json.RawMessage
		if json.Unmarshal(em.Data, &arr) == nil && len(arr) > 0 {
			data, _ = json.Marshal(arr[1:])
		}
	}
	sm := types.StreamMessage{Dir: "out", Type: kind, Event: event, Data: string(data), Encoding: "text",
		Meta: map[string]any{"namespace": sio.NormalizeNamespace(em.Namespace)}}
	if ackID != nil {
		sm.Meta["ack_id"] = *ackID
	}
	if len(em.Buffers) > 0 {
		sm.Meta["attachments"] = len(em.Buffers)
	}
	return sm
}

// resolveAttachments loads attachment payloads into memory (Socket.IO
// requires whole messages), bounded by the upload limit.
func resolveAttachments(d *tools.Deps, ps []types.Payload) ([][]byte, error) {
	var out [][]byte
	limit := d.Cfg.UploadBytes(0)
	for i := range ps {
		if ps[i].IsZero() {
			return nil, fmt.Errorf("attachments[%d]: set base64 or file", i)
		}
		rp, err := ps[i].Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, limit)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d]: %w", i, err)
		}
		b, err := rp.Bytes(limit)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d]: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func registerSIO(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "sio_exchange", "Socket.IO exchange",
		"One-shot Socket.IO (Engine.IO v4 / Socket.IO v5) call: connect over websocket or long-polling, join namespace "+
			"(auth_payload is the CONNECT auth object), emit events[] (JSON args, binary attachments from base64/file, "+
			"optional ack), then collect incoming events and acks until max_messages, max_duration_seconds, "+
			"idle_timeout_seconds or stop_on_event. Events come back as type event with the event name and JSON args; "+
			"acks as type ack with meta.ack_id; binary attachments as {\"_binary\":true,\"base64\":...}. "+
			"Use sio_connect for interactive sessions.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sioExchangeIn) (any, error) {
			return sioExchange(ctx, d, in)
		})
}

type preparedEvent struct {
	sioEvent
	ns   string
	bufs [][]byte
}

func sioExchange(ctx context.Context, d *tools.Deps, in sioExchangeIn) (any, error) {
	_, urlNS, err := in.resolve()
	if err != nil {
		return nil, err
	}
	ns := in.Namespace
	if ns == "" {
		ns = urlNS
	}
	ns = sio.NormalizeNamespace(ns)
	namespaces := []string{ns}
	var events []preparedEvent
	for i, e := range in.Events {
		if e.Event == "" {
			return nil, fmt.Errorf("events[%d]: event name is required", i)
		}
		bufs, err := resolveAttachments(d, e.Attachments)
		if err != nil {
			return nil, fmt.Errorf("events[%d]: %w", i, err)
		}
		pe := preparedEvent{sioEvent: e, ns: ns, bufs: bufs}
		if e.Namespace != "" {
			pe.ns = sio.NormalizeNamespace(e.Namespace)
		}
		if !contains(namespaces, pe.ns) {
			namespaces = append(namespaces, pe.ns)
		}
		events = append(events, pe)
	}
	listen := map[string]bool{}
	for _, l := range in.Listen {
		listen[l] = true
	}

	col := types.NewCollector(d.Cfg.Messages(in.MaxMessages), d.Cfg.StreamDuration(in.MaxDurationSeconds), secs(in.IdleTimeoutSeconds), 0)
	var cl atomic.Pointer[sio.Client]
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	onMessage := func(m sio.Message) {
		switch m.Kind {
		case sio.KindClose:
			if m.Err != "" {
				col.Add(sioMessage(m))
				col.Finish(types.EndedPeerClosed, errors.New(m.Err))
			} else {
				col.Finish(types.EndedPeerClosed, nil)
			}
			return
		case sio.KindEvent:
			if len(listen) > 0 && !listen[m.Event] {
				return
			}
			if in.AutoAck && m.AckID != nil {
				if c := cl.Load(); c != nil {
					id, ns := *m.AckID, m.Namespace
					go func() {
						if pkt, err := c.Ack(runCtx, ns, id, in.AutoAckArgs, nil); err == nil {
							col.Add(outMessage("ack", pkt, "", &id))
						}
					}()
				}
			}
		}
		if !col.Add(sioMessage(m)) {
			return
		}
		if in.StopOnEvent != "" && m.Kind == sio.KindEvent && m.Event == in.StopOnEvent {
			col.Finish(types.EndedStopEvent, nil)
		}
	}
	c, hc, err := in.dial(ctx, d, onMessage)
	if err != nil {
		return nil, err
	}
	defer hc.Close()
	defer c.Close()
	cl.Store(c)

	finish := func() (any, error) {
		res := col.Wait(ctx)
		res.Meta = engineInfo(c)
		if w := in.warnings(); w != nil {
			res.Meta["warnings"] = w
		}
		return res, nil
	}

	for _, n := range namespaces {
		cctx, cancel := context.WithTimeout(ctx, in.connectTimeout(d))
		_, err := c.Connect(cctx, n, in.AuthPayload)
		cancel()
		if err != nil {
			var ce *sio.ConnectError
			if errors.As(err, &ce) {
				col.Add(types.StreamMessage{Dir: "in", Type: sio.KindConnectError, Data: string(ce.Data), Encoding: "text",
					Meta: map[string]any{"namespace": n}})
			}
			col.Finish(types.EndedError, err)
			return finish()
		}
	}

	go func() {
		for i, e := range events {
			if !sleepCtx(runCtx, col.Done(), time.Duration(e.DelayMS)*time.Millisecond) {
				return
			}
			select {
			case <-col.Done():
				return
			default:
			}
			em, err := c.Emit(runCtx, e.ns, e.Event, e.Args, e.bufs, sio.EmitOptions{Ack: e.Ack})
			if err != nil {
				col.Finish(types.EndedError, fmt.Errorf("emitting events[%d]: %w", i, err))
				return
			}
			col.Add(outMessage("event", em.Packet, e.Event, em.AckID))
		}
	}()
	return finish()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
