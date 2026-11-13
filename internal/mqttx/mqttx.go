// Package mqttx is a small MQTT client facade over two libraries:
// github.com/eclipse/paho.golang (MQTT 5 only) and
// github.com/eclipse/paho.mqtt.golang (MQTT 3.1 / 3.1.1). Callers dial the
// network connection themselves (through the SSRF guard, see Dial) and hand
// it to Connect, which picks the right library for the protocol version.
package mqttx

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Protocol versions (the MQTT protocol level byte).
const (
	V31  = 3
	V311 = 4
	V5   = 5
)

// ParseVersion parses a user supplied protocol version. Empty means MQTT 5.
func ParseVersion(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "v"))) {
	case "", "5", "5.0", "mqtt5", "mqttv5":
		return V5, nil
	case "4", "3.1.1", "311", "mqtt3.1.1":
		return V311, nil
	case "3", "3.1", "31":
		return V31, nil
	}
	return 0, fmt.Errorf("unsupported protocol_version %q (use 5, 3.1.1/4 or 3.1/3)", s)
}

// VersionName returns the display name of a protocol level.
func VersionName(v int) string {
	switch v {
	case V5:
		return "5"
	case V311:
		return "3.1.1"
	case V31:
		return "3.1"
	}
	return fmt.Sprint(v)
}

// UserProperty is an MQTT 5 user property (keys may repeat).
type UserProperty struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Properties are the MQTT 5 PUBLISH / will properties.
type Properties struct {
	ContentType     string
	ResponseTopic   string
	CorrelationData []byte
	MessageExpiry   *uint32
	PayloadFormat   *byte
	UserProperties  []UserProperty
	SubscriptionIDs []int
	TopicAlias      *uint16
}

// IsZero reports whether no property is set.
func (p *Properties) IsZero() bool {
	return p == nil || (p.ContentType == "" && p.ResponseTopic == "" && p.CorrelationData == nil &&
		p.MessageExpiry == nil && p.PayloadFormat == nil && len(p.UserProperties) == 0 &&
		len(p.SubscriptionIDs) == 0 && p.TopicAlias == nil)
}

// Map renders the properties for a result. Correlation data is returned as
// text when it is valid UTF-8, otherwise base64 (correlation_data_base64).
func (p *Properties) Map() map[string]any {
	if p.IsZero() {
		return nil
	}
	m := map[string]any{}
	if p.ContentType != "" {
		m["content_type"] = p.ContentType
	}
	if p.ResponseTopic != "" {
		m["response_topic"] = p.ResponseTopic
	}
	if p.CorrelationData != nil {
		if utf8.Valid(p.CorrelationData) {
			m["correlation_data"] = string(p.CorrelationData)
		} else {
			m["correlation_data_base64"] = base64.StdEncoding.EncodeToString(p.CorrelationData)
		}
	}
	if p.MessageExpiry != nil {
		m["message_expiry"] = *p.MessageExpiry
	}
	if p.PayloadFormat != nil {
		m["payload_format"] = *p.PayloadFormat
	}
	if len(p.UserProperties) > 0 {
		m["user_properties"] = p.UserProperties
	}
	if len(p.SubscriptionIDs) > 0 {
		m["subscription_identifiers"] = p.SubscriptionIDs
	}
	if p.TopicAlias != nil {
		m["topic_alias"] = *p.TopicAlias
	}
	return m
}

// UserPropertiesFromMap converts a map to user properties in key order.
func UserPropertiesFromMap(m map[string]string) []UserProperty {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]UserProperty, 0, len(keys))
	for _, k := range keys {
		out = append(out, UserProperty{Key: k, Value: m[k]})
	}
	return out
}

// Message is a PUBLISH, sent or received.
type Message struct {
	Topic    string
	Payload  []byte
	QoS      byte
	Retain   bool
	Dup      bool
	PacketID uint16
	Props    *Properties // MQTT 5 only
}

// Will is the last-will message carried in CONNECT.
type Will struct {
	Topic         string
	Payload       []byte
	QoS           byte
	Retain        bool
	Props         *Properties // MQTT 5 only
	DelayInterval *uint32     // MQTT 5 only (seconds)
}

// Config describes one client connection.
type Config struct {
	Version       int
	Conn          net.Conn // already established (TLS / WebSocket applied)
	ClientID      string
	CleanStart    bool
	SessionExpiry *uint32 // MQTT 5 only
	KeepAlive     uint16  // seconds; 0 disables keepalive
	Username      string  // sent when non-empty
	Password      string  // sent when non-empty
	Will          *Will
	PacketTimeout time.Duration
	// OnMessage is called for every received PUBLISH. It must not block.
	OnMessage func(Message)
	// OnLost is called once when the connection drops or the broker sends
	// DISCONNECT (not after Disconnect).
	OnLost func(error)
}

// Connack summarises the broker's CONNACK.
type Connack struct {
	ReasonCode     byte           `json:"reason_code"`
	Reason         string         `json:"reason"`
	SessionPresent bool           `json:"session_present"`
	Properties     map[string]any `json:"properties,omitempty"`
}

// PubAck summarises the acknowledgement flow of a PUBLISH.
type PubAck struct {
	// Kind is "none" (QoS 0), "PUBACK" (QoS 1), "PUBCOMP" (QoS 2) or
	// "PUBREC" (QoS 2 refused by the broker).
	Kind           string         `json:"kind"`
	PacketID       uint16         `json:"packet_id"`
	ReasonCode     byte           `json:"reason_code"`
	Reason         string         `json:"reason"`
	OK             bool           `json:"ok"`
	ReasonString   string         `json:"reason_string,omitempty"`
	UserProperties []UserProperty `json:"user_properties,omitempty"`
}

// Subscription is one topic filter in a SUBSCRIBE.
type Subscription struct {
	Filter            string
	QoS               byte
	NoLocal           bool // MQTT 5
	RetainAsPublished bool // MQTT 5
	RetainHandling    byte // MQTT 5: 0 send retained, 1 only for new subscriptions, 2 never
}

// SubResult is the broker's answer for one filter.
type SubResult struct {
	Filter       string `json:"filter"`
	RequestedQoS byte   `json:"requested_qos"`
	ReasonCode   byte   `json:"reason_code"`
	Reason       string `json:"reason"`
	Granted      bool   `json:"granted"`
	GrantedQoS   *byte  `json:"granted_qos,omitempty"`
}

// Client is a connected MQTT client.
type Client interface {
	Version() int
	ClientID() string
	Publish(ctx context.Context, m Message) (*PubAck, error)
	Subscribe(ctx context.Context, subs []Subscription) ([]SubResult, error)
	// Disconnect closes the session. withWill asks the broker to publish
	// the will message (MQTT 5 reason 0x04; for 3.1.x the network
	// connection is dropped without DISCONNECT).
	Disconnect(withWill bool)
}

// Connect performs the MQTT handshake on cfg.Conn. On a refused connection
// it returns the Connack (when one was received) together with an error.
// The connection is closed on error.
func Connect(ctx context.Context, cfg Config) (Client, *Connack, error) {
	if cfg.Conn == nil {
		return nil, nil, fmt.Errorf("mqttx: no connection")
	}
	if cfg.PacketTimeout <= 0 {
		cfg.PacketTimeout = 30 * time.Second
	}
	switch cfg.Version {
	case V5:
		return connectV5(ctx, cfg)
	case V311, V31:
		return connectV3(ctx, cfg)
	}
	cfg.Conn.Close()
	return nil, nil, fmt.Errorf("mqttx: unsupported protocol version %d", cfg.Version)
}

func subResult(s Subscription, code byte, v5 bool) SubResult {
	r := SubResult{Filter: s.Filter, RequestedQoS: s.QoS, ReasonCode: code}
	if code <= 2 {
		q := code
		r.Granted = true
		r.GrantedQoS = &q
		r.Reason = fmt.Sprintf("Granted QoS %d", code)
	} else if v5 {
		r.Reason = ReasonName(code)
	} else {
		r.Reason = "Failure"
	}
	return r
}

// ReasonName returns the MQTT 5 reason code name.
func ReasonName(code byte) string {
	if n, ok := reasonNames[code]; ok {
		return n
	}
	return fmt.Sprintf("Unknown reason 0x%02x", code)
}

var reasonNames = map[byte]string{
	0x00: "Success",
	0x01: "Granted QoS 1",
	0x02: "Granted QoS 2",
	0x04: "Disconnect with Will Message",
	0x10: "No matching subscribers",
	0x11: "No subscription existed",
	0x18: "Continue authentication",
	0x19: "Re-authenticate",
	0x80: "Unspecified error",
	0x81: "Malformed Packet",
	0x82: "Protocol Error",
	0x83: "Implementation specific error",
	0x84: "Unsupported Protocol Version",
	0x85: "Client Identifier not valid",
	0x86: "Bad User Name or Password",
	0x87: "Not authorized",
	0x88: "Server unavailable",
	0x89: "Server busy",
	0x8A: "Banned",
	0x8B: "Server shutting down",
	0x8C: "Bad authentication method",
	0x8D: "Keep Alive timeout",
	0x8E: "Session taken over",
	0x8F: "Topic Filter invalid",
	0x90: "Topic Name invalid",
	0x91: "Packet Identifier in use",
	0x92: "Packet Identifier not found",
	0x93: "Receive Maximum exceeded",
	0x94: "Topic Alias invalid",
	0x95: "Packet too large",
	0x96: "Message rate too high",
	0x97: "Quota exceeded",
	0x98: "Administrative action",
	0x99: "Payload format invalid",
	0x9A: "Retain not supported",
	0x9B: "QoS not supported",
	0x9C: "Use another server",
	0x9D: "Server moved",
	0x9E: "Shared Subscriptions not supported",
	0x9F: "Connection rate exceeded",
	0xA0: "Maximum connect time",
	0xA1: "Subscription Identifiers not supported",
	0xA2: "Wildcard Subscriptions not supported",
}

// V3ConnackName returns the MQTT 3.1.1 CONNACK return code name.
func V3ConnackName(code byte) string {
	switch code {
	case 0:
		return "Connection Accepted"
	case 1:
		return "Connection Refused: unacceptable protocol version"
	case 2:
		return "Connection Refused: identifier rejected"
	case 3:
		return "Connection Refused: server unavailable"
	case 4:
		return "Connection Refused: bad user name or password"
	case 5:
		return "Connection Refused: not authorized"
	}
	return fmt.Sprintf("Connection Refused: unknown return code %d", code)
}

// ValidateTopicName checks a PUBLISH topic (no wildcards).
func ValidateTopicName(t string) error {
	if t == "" {
		return fmt.Errorf("topic is required")
	}
	if strings.ContainsAny(t, "+#") {
		return fmt.Errorf("topic %q contains a wildcard (+ or #); wildcards are only valid in subscription filters", t)
	}
	if strings.ContainsRune(t, 0) {
		return fmt.Errorf("topic contains a NUL character")
	}
	return nil
}

// ValidateFilter checks a subscription topic filter, including shared
// subscriptions ($share/group/filter).
func ValidateFilter(f string) error {
	if f == "" {
		return fmt.Errorf("topic filter is empty")
	}
	inner := f
	if strings.HasPrefix(f, "$share/") {
		rest := strings.TrimPrefix(f, "$share/")
		i := strings.IndexByte(rest, '/')
		if i <= 0 || i == len(rest)-1 {
			return fmt.Errorf("shared subscription %q must look like $share/<group>/<filter>", f)
		}
		if strings.ContainsAny(rest[:i], "+#") {
			return fmt.Errorf("shared subscription group name in %q must not contain wildcards", f)
		}
		inner = rest[i+1:]
	}
	levels := strings.Split(inner, "/")
	for i, l := range levels {
		if strings.Contains(l, "#") && (l != "#" || i != len(levels)-1) {
			return fmt.Errorf("topic filter %q: '#' must be the last level on its own", f)
		}
		if strings.Contains(l, "+") && l != "+" {
			return fmt.Errorf("topic filter %q: '+' must occupy an entire level", f)
		}
	}
	return nil
}
