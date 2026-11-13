package amqpx

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Properties are the basic.publish message properties (tool input shape).
type Properties struct {
	ContentType     string         `json:"content_type,omitempty" jsonschema:"MIME type (default: derived from the payload kind)"`
	ContentEncoding string         `json:"content_encoding,omitempty" jsonschema:"MIME content encoding, e.g. gzip"`
	DeliveryMode    int            `json:"delivery_mode,omitempty" jsonschema:"1 = transient, 2 = persistent"`
	Persistent      bool           `json:"persistent,omitempty" jsonschema:"shortcut for delivery_mode=2"`
	Priority        int            `json:"priority,omitempty" jsonschema:"message priority 0-9"`
	CorrelationID   string         `json:"correlation_id,omitempty"`
	ReplyTo         string         `json:"reply_to,omitempty"`
	Expiration      string         `json:"expiration,omitempty" jsonschema:"per-message TTL in milliseconds as a string, e.g. \"60000\""`
	MessageID       string         `json:"message_id,omitempty"`
	Timestamp       string         `json:"timestamp,omitempty" jsonschema:"RFC 3339 time, unix seconds, or \"now\""`
	Type            string         `json:"type,omitempty" jsonschema:"application message type name"`
	UserID          string         `json:"user_id,omitempty" jsonschema:"must match the authenticated user on RabbitMQ"`
	AppID           string         `json:"app_id,omitempty"`
	Headers         map[string]any `json:"headers,omitempty" jsonschema:"application headers table (strings, numbers, booleans, nested objects, arrays)"`
}

// Publishing builds an amqp.Publishing. defaultContentType is used when no
// content type is set (pass "" for none).
func (p *Properties) Publishing(body []byte, defaultContentType string) (amqp.Publishing, error) {
	if p == nil {
		p = &Properties{}
	}
	pub := amqp.Publishing{
		ContentType:     p.ContentType,
		ContentEncoding: p.ContentEncoding,
		CorrelationId:   p.CorrelationID,
		ReplyTo:         p.ReplyTo,
		Expiration:      strings.TrimSpace(p.Expiration),
		MessageId:       p.MessageID,
		Type:            p.Type,
		UserId:          p.UserID,
		AppId:           p.AppID,
		Body:            body,
	}
	if pub.ContentType == "" {
		pub.ContentType = defaultContentType
	}
	switch {
	case p.DeliveryMode < 0 || p.DeliveryMode > 2:
		return pub, fmt.Errorf("delivery_mode must be 1 (transient) or 2 (persistent)")
	case p.Persistent:
		pub.DeliveryMode = amqp.Persistent
	default:
		pub.DeliveryMode = uint8(p.DeliveryMode)
	}
	if p.Priority < 0 || p.Priority > 255 {
		return pub, fmt.Errorf("priority must be between 0 and 9 (255 max)")
	}
	pub.Priority = uint8(p.Priority)
	if pub.Expiration != "" {
		if n, err := strconv.ParseInt(pub.Expiration, 10, 64); err != nil || n < 0 {
			return pub, fmt.Errorf("expiration must be a non-negative number of milliseconds as a string, got %q", p.Expiration)
		}
	}
	if p.Timestamp != "" {
		ts, err := ParseTime(p.Timestamp)
		if err != nil {
			return pub, fmt.Errorf("timestamp: %w", err)
		}
		pub.Timestamp = ts
	}
	h, err := ToTable(p.Headers)
	if err != nil {
		return pub, fmt.Errorf("headers: %w", err)
	}
	pub.Headers = h
	return pub, nil
}

// ParseTime accepts "now", RFC 3339, or unix seconds.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "now") {
		return time.Now(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC 3339, unix seconds or \"now\", got %q", s)
	}
	return t, nil
}

// DeliveryProperties returns the non-empty message properties of a delivery
// as a JSON-friendly map.
func DeliveryProperties(d *amqp.Delivery) map[string]any {
	m := map[string]any{}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("content_type", d.ContentType)
	set("content_encoding", d.ContentEncoding)
	if d.DeliveryMode != 0 {
		m["delivery_mode"] = d.DeliveryMode
	}
	if d.Priority != 0 {
		m["priority"] = d.Priority
	}
	set("correlation_id", d.CorrelationId)
	set("reply_to", d.ReplyTo)
	set("expiration", d.Expiration)
	set("message_id", d.MessageId)
	if !d.Timestamp.IsZero() {
		m["timestamp"] = d.Timestamp.UTC().Format(time.RFC3339)
	}
	set("type", d.Type)
	set("user_id", d.UserId)
	set("app_id", d.AppId)
	if h := FromTable(d.Headers); h != nil {
		m["headers"] = h
	}
	return m
}
