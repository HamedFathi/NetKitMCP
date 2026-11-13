package msgtools

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/mqttx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupMQTT, registerMQTT) }

// mqttMaxPayload is the MQTT protocol limit for a packet body.
const mqttMaxPayload = 268435455

// MQTTProps are MQTT 5 message properties.
type MQTTProps struct {
	ContentType           string            `json:"content_type,omitempty" jsonschema:"MQTT 5 content type (e.g. application/json)"`
	ResponseTopic         string            `json:"response_topic,omitempty" jsonschema:"MQTT 5 response topic for request/response"`
	CorrelationData       string            `json:"correlation_data,omitempty" jsonschema:"MQTT 5 correlation data as text"`
	CorrelationDataBase64 string            `json:"correlation_data_base64,omitempty" jsonschema:"MQTT 5 correlation data as base64 (binary)"`
	MessageExpiry         *uint32           `json:"message_expiry,omitempty" jsonschema:"MQTT 5 message expiry interval in seconds"`
	PayloadFormat         *int              `json:"payload_format,omitempty" jsonschema:"MQTT 5 payload format indicator: 0 = bytes, 1 = UTF-8 text"`
	UserProperties        map[string]string `json:"user_properties,omitempty" jsonschema:"MQTT 5 user properties (key/value)"`
}

func (p *MQTTProps) toProps() (*mqttx.Properties, error) {
	if p == nil {
		return nil, nil
	}
	out := &mqttx.Properties{
		ContentType:    p.ContentType,
		ResponseTopic:  p.ResponseTopic,
		MessageExpiry:  p.MessageExpiry,
		UserProperties: mqttx.UserPropertiesFromMap(p.UserProperties),
	}
	if p.ResponseTopic != "" {
		if err := mqttx.ValidateTopicName(p.ResponseTopic); err != nil {
			return nil, fmt.Errorf("response_topic: %w", err)
		}
	}
	switch {
	case p.CorrelationData != "" && p.CorrelationDataBase64 != "":
		return nil, fmt.Errorf("set only one of correlation_data and correlation_data_base64")
	case p.CorrelationData != "":
		out.CorrelationData = []byte(p.CorrelationData)
	case p.CorrelationDataBase64 != "":
		b, err := types.DecodeBase64(p.CorrelationDataBase64)
		if err != nil {
			return nil, fmt.Errorf("correlation_data_base64: %w", err)
		}
		out.CorrelationData = b
	}
	if p.PayloadFormat != nil {
		if *p.PayloadFormat != 0 && *p.PayloadFormat != 1 {
			return nil, fmt.Errorf("payload_format must be 0 or 1")
		}
		b := byte(*p.PayloadFormat)
		out.PayloadFormat = &b
	}
	if out.IsZero() {
		return nil, nil
	}
	return out, nil
}

// MQTTWill is the last-will message.
type MQTTWill struct {
	Topic        string         `json:"topic" jsonschema:"will topic"`
	Payload      *types.Payload `json:"payload,omitempty" jsonschema:"will payload"`
	QoS          int            `json:"qos,omitempty" jsonschema:"will QoS 0-2"`
	Retain       bool           `json:"retain,omitempty" jsonschema:"retain the will message"`
	DelaySeconds *uint32        `json:"delay_seconds,omitempty" jsonschema:"MQTT 5 will delay interval in seconds"`
	Properties   *MQTTProps     `json:"properties,omitempty" jsonschema:"MQTT 5 will properties"`
}

// MQTTConnArgs are the connection arguments shared by the MQTT tools.
type MQTTConnArgs struct {
	Broker               string            `json:"broker" jsonschema:"broker URL: tcp:// or mqtt:// (1883), ssl:// tls:// or mqtts:// (8883), ws:// or wss:// (path defaults to /mqtt); bare host:port means tcp://"`
	ProtocolVersion      string            `json:"protocol_version,omitempty" jsonschema:"5 (default) or 3.1.1 (also 4); 3.1 for very old brokers"`
	ClientID             string            `json:"client_id,omitempty" jsonschema:"client identifier (default: random netkit-...)"`
	CleanStart           *bool             `json:"clean_start,omitempty" jsonschema:"MQTT 5 clean start / 3.1.1 clean session (default true)"`
	CleanSession         *bool             `json:"clean_session,omitempty" jsonschema:"alias of clean_start"`
	SessionExpirySeconds *uint32           `json:"session_expiry_seconds,omitempty" jsonschema:"MQTT 5 session expiry interval in seconds"`
	KeepAliveSeconds     *int              `json:"keepalive_seconds,omitempty" jsonschema:"keepalive in seconds (default 30, 0 disables)"`
	Username             string            `json:"username,omitempty" jsonschema:"broker username (overrides auth)"`
	Password             string            `json:"password,omitempty" jsonschema:"broker password (overrides auth)"`
	Auth                 *auth.Config      `json:"auth,omitempty" jsonschema:"auth object: basic (username/password), bearer (token sent as the password) or mtls"`
	Will                 *MQTTWill         `json:"will,omitempty" jsonschema:"last-will message"`
	DisconnectWithWill   bool              `json:"disconnect_with_will,omitempty" jsonschema:"end the session so the broker publishes the will (MQTT 5 reason 0x04; 3.1.x drops the connection)"`
	WSHeaders            map[string]string `json:"ws_headers,omitempty" jsonschema:"extra HTTP headers for the ws:// / wss:// handshake"`
	types.NetOptions
}

type mqttSession struct {
	client   mqttx.Client
	connack  *mqttx.Connack
	broker   string
	version  int
	tls      *types.TLSInfo
	warnings []string
	connect  time.Duration
}

func (a *MQTTConnArgs) credentials(u *url.URL) (string, string, error) {
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if a.Auth != nil {
		switch k := a.Auth.Kind(); k {
		case "none", "mtls":
		default:
			au, ap, ok := auth.UserPass(a.Auth)
			if !ok {
				return "", "", fmt.Errorf("auth type %q is not supported for MQTT; use basic (username/password), bearer (token sent as password), mtls, or the username/password arguments", k)
			}
			user, pass = au, ap
		}
	}
	if a.Username != "" {
		user = a.Username
	}
	if a.Password != "" {
		pass = a.Password
	}
	return user, pass, nil
}

// connect dials (through the SSRF guard) and performs the MQTT handshake.
func (a *MQTTConnArgs) connect(ctx context.Context, d *tools.Deps, onMsg func(mqttx.Message), onLost func(error)) (*mqttSession, error) {
	u, err := mqttx.ParseBroker(a.Broker)
	if err != nil {
		return nil, err
	}
	version, err := mqttx.ParseVersion(a.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	user, pass, err := a.credentials(u)
	if err != nil {
		return nil, err
	}
	if a.Auth != nil {
		auth.ApplyTLS(a.Auth, &a.TLSOptions)
	}
	s := &mqttSession{broker: redact.URL(u.String()), version: version}
	useTLS := mqttx.IsTLS(u.Scheme)
	s.warnings = append(s.warnings, insecureWarning(a.TLSOptions, useTLS)...)
	if !useTLS && (a.CACert != "" || a.ClientCert != "" || a.InsecureSkipVerify) {
		s.warnings = append(s.warnings, fmt.Sprintf("TLS options are ignored for %s://; use ssl://, mqtts:// or wss://", u.Scheme))
	}
	if version != mqttx.V5 {
		if a.SessionExpirySeconds != nil {
			s.warnings = append(s.warnings, "session_expiry_seconds is MQTT 5 only; ignored")
		}
		if a.DisconnectWithWill {
			s.warnings = append(s.warnings, "MQTT 3.1.x has no disconnect-with-will; the connection is dropped instead")
		}
	}
	if user == "" && pass != "" && version != mqttx.V5 {
		s.warnings = append(s.warnings, "MQTT 3.1.x requires a username when a password is set; the broker may reject the connection")
	}

	timeout := d.Cfg.Timeout(a.TimeoutSeconds)
	dialer := d.Guard.Dialer(a.AllowPrivate, timeout)
	dc := mqttx.DialConfig{URL: u, Dialer: dialer, Header: tools.Headers(a.WSHeaders)}
	if mqttx.IsWebSocket(u.Scheme) {
		hc, err := d.NewHTTPClient(types.HTTPOptions{NetOptions: a.NetOptions, HTTPVersion: "1.1"}, nil)
		if err != nil {
			return nil, err
		}
		defer hc.Close()
		dc.HTTPClient = hc.Client
	} else if useTLS {
		tc, err := tlsx.Config(d.Files, a.TLSOptions, u.Hostname(), nil)
		if err != nil {
			return nil, err
		}
		dc.TLS = tc
	}

	start := time.Now()
	conn, cs, err := mqttx.Dial(ctx, dc)
	if err != nil {
		return nil, err
	}
	if cs != nil {
		s.tls = tlsx.Info(cs, a.InsecureSkipVerify)
	}

	clean := true
	if a.CleanStart != nil {
		clean = *a.CleanStart
	} else if a.CleanSession != nil {
		clean = *a.CleanSession
	}
	keep := 30
	if a.KeepAliveSeconds != nil {
		keep = *a.KeepAliveSeconds
	}
	if keep < 0 || keep > 65535 {
		conn.Close()
		return nil, fmt.Errorf("keepalive_seconds must be 0-65535")
	}
	cid := a.ClientID
	if cid == "" {
		cid = randomID("netkit-")
	}
	cfg := mqttx.Config{
		Version:       version,
		Conn:          conn,
		ClientID:      cid,
		CleanStart:    clean,
		KeepAlive:     uint16(keep),
		Username:      user,
		Password:      pass,
		PacketTimeout: timeout,
		OnMessage:     onMsg,
		OnLost:        onLost,
	}
	if version == mqttx.V5 {
		cfg.SessionExpiry = a.SessionExpirySeconds
	}
	if w := a.Will; w != nil {
		if err := mqttx.ValidateTopicName(w.Topic); err != nil {
			conn.Close()
			return nil, fmt.Errorf("will: %w", err)
		}
		q, err := qosByte(w.QoS, "will.qos")
		if err != nil {
			conn.Close()
			return nil, err
		}
		pd, err := resolvePayload(d, w.Payload, 1<<20)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("will payload: %w", err)
		}
		props, err := w.Properties.toProps()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("will properties: %w", err)
		}
		mw := &mqttx.Will{Topic: w.Topic, Payload: pd.Data, QoS: q, Retain: w.Retain}
		if version == mqttx.V5 {
			mw.Props = props
			mw.DelayInterval = w.DelaySeconds
		} else if props != nil || w.DelaySeconds != nil {
			s.warnings = append(s.warnings, "will properties and delay are MQTT 5 only; ignored")
		}
		cfg.Will = mw
	}
	client, connack, err := mqttx.Connect(ctx, cfg)
	s.connack = connack
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.broker, err)
	}
	s.client = client
	s.connect = time.Since(start)
	return s, nil
}

func (s *mqttSession) close(withWill bool) {
	if s.client != nil {
		s.client.Disconnect(withWill)
	}
}

// MQTTPublishArgs are the mqtt_publish arguments.
type MQTTPublishArgs struct {
	MQTTConnArgs
	Topic      string         `json:"topic" jsonschema:"topic name (no wildcards)"`
	Payload    *types.Payload `json:"payload,omitempty" jsonschema:"message payload: text, json, base64 or file (omit for an empty payload)"`
	QoS        int            `json:"qos,omitempty" jsonschema:"QoS 0 (default), 1 or 2"`
	Retain     bool           `json:"retain,omitempty" jsonschema:"set the retain flag (an empty retained payload clears the retained message)"`
	Properties *MQTTProps     `json:"properties,omitempty" jsonschema:"MQTT 5 publish properties"`
}

type mqttSent struct {
	Topic       string          `json:"topic"`
	Bytes       int             `json:"bytes"`
	QoS         int             `json:"qos"`
	Retain      bool            `json:"retain"`
	PacketID    uint16          `json:"packet_id"`
	Properties  map[string]any  `json:"properties,omitempty"`
	PayloadFile *types.FileInfo `json:"payload_file,omitempty"`
}

type mqttPublishOut struct {
	Broker          string         `json:"broker"`
	ProtocolVersion string         `json:"protocol_version"`
	ClientID        string         `json:"client_id"`
	Connack         *mqttx.Connack `json:"connack"`
	Published       mqttSent       `json:"published"`
	Ack             *mqttx.PubAck  `json:"ack"`
	TLS             *types.TLSInfo `json:"tls,omitempty"`
	TimingMS        timingMS       `json:"timing_ms"`
	Warnings        []string       `json:"warnings,omitempty"`
}

// mqttMessage holds a message to publish (mqtt_publish or publish_first).
type mqttMessage struct {
	Topic      string
	Payload    *types.Payload
	QoS        int
	Retain     bool
	Properties *MQTTProps
}

func (m mqttMessage) build(d *tools.Deps, version int) (mqttx.Message, mqttSent, []string, error) {
	var warnings []string
	if err := mqttx.ValidateTopicName(m.Topic); err != nil {
		return mqttx.Message{}, mqttSent{}, nil, err
	}
	q, err := qosByte(m.QoS, "qos")
	if err != nil {
		return mqttx.Message{}, mqttSent{}, nil, err
	}
	pd, err := resolvePayload(d, m.Payload, mqttMaxPayload)
	if err != nil {
		return mqttx.Message{}, mqttSent{}, nil, err
	}
	props, err := m.Properties.toProps()
	if err != nil {
		return mqttx.Message{}, mqttSent{}, nil, err
	}
	if props != nil && version != mqttx.V5 {
		warnings = append(warnings, "message properties are MQTT 5 only; ignored for MQTT "+mqttx.VersionName(version))
		props = nil
	}
	msg := mqttx.Message{Topic: m.Topic, Payload: pd.Data, QoS: q, Retain: m.Retain, Props: props}
	sent := mqttSent{Topic: m.Topic, Bytes: len(pd.Data), QoS: int(q), Retain: m.Retain, Properties: props.Map(), PayloadFile: pd.File}
	return msg, sent, warnings, nil
}

func publishMQTT(ctx context.Context, d *tools.Deps, in MQTTPublishArgs) (any, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(in.TimeoutSeconds))
	defer cancel()
	version, err := mqttx.ParseVersion(in.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	m := mqttMessage{Topic: in.Topic, Payload: in.Payload, QoS: in.QoS, Retain: in.Retain, Properties: in.Properties}
	msg, sent, warnings, err := m.build(d, version)
	if err != nil {
		return nil, err
	}
	s, err := in.connect(ctx, d, nil, nil)
	if err != nil {
		return nil, err
	}
	defer s.close(in.DisconnectWithWill)
	pubStart := time.Now()
	ack, err := s.client.Publish(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.broker, err)
	}
	sent.PacketID = ack.PacketID
	out := mqttPublishOut{
		Broker:          s.broker,
		ProtocolVersion: mqttx.VersionName(s.version),
		ClientID:        s.client.ClientID(),
		Connack:         s.connack,
		Published:       sent,
		Ack:             ack,
		TLS:             s.tls,
		Warnings:        append(s.warnings, warnings...),
	}
	out.TimingMS.Connect = types.MS(s.connect)
	out.TimingMS.Op = types.MS(time.Since(pubStart))
	out.TimingMS.Total = types.MS(time.Since(start))
	return out, nil
}

// MQTTFilter is one subscription.
type MQTTFilter struct {
	Filter            string `json:"filter" jsonschema:"topic filter; wildcards + (one level) and # (rest); shared: $share/<group>/<filter>"`
	QoS               *int   `json:"qos,omitempty" jsonschema:"maximum QoS for this filter (default: the top-level qos)"`
	NoLocal           bool   `json:"no_local,omitempty" jsonschema:"MQTT 5: do not receive messages published by this client"`
	RetainAsPublished bool   `json:"retain_as_published,omitempty" jsonschema:"MQTT 5: keep the original retain flag"`
	RetainHandling    int    `json:"retain_handling,omitempty" jsonschema:"MQTT 5: 0 send retained messages, 1 only for new subscriptions, 2 never"`
}

// MQTTPublishFirst is a message published right after subscribing.
type MQTTPublishFirst struct {
	Topic      string         `json:"topic" jsonschema:"topic to publish to"`
	Payload    *types.Payload `json:"payload,omitempty" jsonschema:"payload: text, json, base64 or file"`
	QoS        int            `json:"qos,omitempty" jsonschema:"QoS 0-2"`
	Retain     bool           `json:"retain,omitempty" jsonschema:"retain flag"`
	Properties *MQTTProps     `json:"properties,omitempty" jsonschema:"MQTT 5 properties (e.g. response_topic, correlation_data)"`
}

// MQTTSubscribeArgs are the mqtt_subscribe arguments.
type MQTTSubscribeArgs struct {
	MQTTConnArgs
	Topic        string            `json:"topic,omitempty" jsonschema:"single topic filter (shortcut for topics)"`
	Topics       []MQTTFilter      `json:"topics,omitempty" jsonschema:"topic filters with per-filter options"`
	QoS          int               `json:"qos,omitempty" jsonschema:"default maximum QoS 0-2 (default 0)"`
	PublishFirst *MQTTPublishFirst `json:"publish_first,omitempty" jsonschema:"publish this message after subscribing (request/response testing)"`
	types.StreamLimits
}

func mqttStreamMessage(m mqttx.Message) types.StreamMessage {
	ct := ""
	if m.Props != nil {
		ct = m.Props.ContentType
	}
	data, enc := types.EncodeBody(m.Payload, ct)
	meta := map[string]any{"qos": m.QoS, "retain": m.Retain, "size_bytes": len(m.Payload)}
	if m.Dup {
		meta["dup"] = true
	}
	if m.PacketID != 0 {
		meta["packet_id"] = m.PacketID
	}
	if pm := m.Props.Map(); pm != nil {
		meta["properties"] = pm
	}
	return types.StreamMessage{Dir: "in", Type: "message", Topic: m.Topic, Data: data, Encoding: enc, Meta: meta}
}

func subscribeMQTT(ctx context.Context, d *tools.Deps, in MQTTSubscribeArgs) (any, error) {
	version, err := mqttx.ParseVersion(in.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	defQoS, err := qosByte(in.QoS, "qos")
	if err != nil {
		return nil, err
	}
	var subs []mqttx.Subscription
	var warnings []string
	if in.Topic != "" {
		in.Topics = append([]MQTTFilter{{Filter: in.Topic}}, in.Topics...)
	}
	if len(in.Topics) == 0 {
		return nil, fmt.Errorf("set topic or topics (e.g. sensors/+/temperature or #)")
	}
	for i, f := range in.Topics {
		if err := mqttx.ValidateFilter(f.Filter); err != nil {
			return nil, err
		}
		q := defQoS
		if f.QoS != nil {
			if q, err = qosByte(*f.QoS, fmt.Sprintf("topics[%d].qos", i)); err != nil {
				return nil, err
			}
		}
		if f.RetainHandling < 0 || f.RetainHandling > 2 {
			return nil, fmt.Errorf("topics[%d].retain_handling must be 0, 1 or 2", i)
		}
		if version != mqttx.V5 && (f.NoLocal || f.RetainAsPublished || f.RetainHandling != 0) {
			warnings = append(warnings, fmt.Sprintf("topics[%d]: no_local / retain_as_published / retain_handling are MQTT 5 only; ignored", i))
		}
		subs = append(subs, mqttx.Subscription{Filter: f.Filter, QoS: q, NoLocal: f.NoLocal, RetainAsPublished: f.RetainAsPublished, RetainHandling: byte(f.RetainHandling)})
	}
	var first *mqttx.Message
	var firstSent mqttSent
	if pf := in.PublishFirst; pf != nil {
		m := mqttMessage{Topic: pf.Topic, Payload: pf.Payload, QoS: pf.QoS, Retain: pf.Retain, Properties: pf.Properties}
		msg, sent, w, err := m.build(d, version)
		if err != nil {
			return nil, fmt.Errorf("publish_first: %w", err)
		}
		first, firstSent = &msg, sent
		warnings = append(warnings, w...)
	}

	n, dur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	col := types.NewCollector(n, dur, idle, 0)
	onMsg := func(m mqttx.Message) {
		m.Payload = append([]byte(nil), m.Payload...)
		col.Add(mqttStreamMessage(m))
	}
	onLost := func(err error) { col.Finish(types.EndedPeerClosed, err) }

	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s, err := in.connect(cctx, d, onMsg, onLost)
	if err != nil {
		return nil, err
	}
	defer s.close(in.DisconnectWithWill)
	results, err := s.client.Subscribe(cctx, subs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.broker, err)
	}
	granted := 0
	for _, r := range results {
		if r.Granted {
			granted++
		}
	}
	meta := map[string]any{
		"broker":           s.broker,
		"protocol_version": mqttx.VersionName(s.version),
		"client_id":        s.client.ClientID(),
		"connack":          s.connack,
		"subscriptions":    results,
	}
	if s.tls != nil {
		meta["tls"] = s.tls
	}
	warnings = append(s.warnings, warnings...)
	if granted == 0 {
		res := col.Result()
		res.EndedBy = types.EndedError
		res.Error = "the broker rejected every subscription (see meta.subscriptions)"
		meta["warnings"] = warnings
		res.Meta = meta
		return res, nil
	}
	if first != nil {
		// Record the outgoing message first: the echo may arrive before
		// the QoS 1/2 flow completes.
		data, enc := types.EncodeBody(first.Payload, "")
		col.Add(types.StreamMessage{Dir: "out", Type: "message", Topic: first.Topic, Data: data, Encoding: enc,
			Meta: map[string]any{"qos": first.QoS, "retain": first.Retain}})
		ack, err := s.client.Publish(cctx, *first)
		if err != nil {
			return nil, fmt.Errorf("publish_first: %w", err)
		}
		firstSent.PacketID = ack.PacketID
		meta["published"] = map[string]any{"message": firstSent, "ack": ack}
	}
	res := col.Wait(ctx)
	if len(warnings) > 0 {
		meta["warnings"] = warnings
	}
	res.Meta = meta
	return res, nil
}

func registerMQTT(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "mqtt_publish", "MQTT publish",
		"Publish one message to an MQTT broker (MQTT 5 by default, or 3.1.1) and report the broker's CONNACK and PUBACK/PUBCOMP reason codes. "+
			"Supports tcp/ssl/ws/wss brokers, QoS 0-2, retain, MQTT 5 properties (content_type, response_topic, correlation_data, message_expiry, user_properties), "+
			"username/password or auth, TLS/mTLS and a last will. The payload may be text, JSON, base64 or a file from an allowed directory (buffered in memory, bounded by the upload limit).",
		tools.Mutating, func(ctx context.Context, _ *mcp.CallToolRequest, in MQTTPublishArgs) (any, error) {
			return publishMQTT(ctx, d, in)
		})
	tools.Add(s, d, "mqtt_subscribe", "MQTT subscribe",
		"Subscribe to MQTT topic filters (wildcards + and #, shared subscriptions $share/group/filter) and collect messages until max_messages, "+
			"max_duration_seconds (default 10) or idle_timeout_seconds. Per-filter QoS and MQTT 5 options (no_local, retain_as_published, retain_handling). "+
			"Retained messages arrive first. publish_first sends a message after subscribing, for request/response tests. Payloads are returned as text or base64 with QoS, retain and properties.",
		tools.ReadOnly, func(ctx context.Context, _ *mcp.CallToolRequest, in MQTTSubscribeArgs) (any, error) {
			return subscribeMQTT(ctx, d, in)
		})
}
