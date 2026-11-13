package mqttx

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse/paho.golang/paho"
)

type v5Client struct {
	c       *paho.Client
	conn    *packetConn
	id      string
	closing atomic.Bool
	lostMu  sync.Once
}

func toV5User(u []UserProperty) paho.UserProperties {
	if len(u) == 0 {
		return nil
	}
	out := make(paho.UserProperties, 0, len(u))
	for _, p := range u {
		out = append(out, paho.UserProperty{Key: p.Key, Value: p.Value})
	}
	return out
}

func fromV5User(u paho.UserProperties) []UserProperty {
	if len(u) == 0 {
		return nil
	}
	out := make([]UserProperty, 0, len(u))
	for _, p := range u {
		out = append(out, UserProperty{Key: p.Key, Value: p.Value})
	}
	return out
}

func toV5PubProps(p *Properties) *paho.PublishProperties {
	if p.IsZero() {
		return nil
	}
	return &paho.PublishProperties{
		ContentType:     p.ContentType,
		ResponseTopic:   p.ResponseTopic,
		CorrelationData: p.CorrelationData,
		MessageExpiry:   p.MessageExpiry,
		PayloadFormat:   p.PayloadFormat,
		User:            toV5User(p.UserProperties),
		TopicAlias:      p.TopicAlias,
	}
}

func fromV5PubProps(p *paho.PublishProperties) *Properties {
	if p == nil {
		return nil
	}
	out := &Properties{
		ContentType:     p.ContentType,
		ResponseTopic:   p.ResponseTopic,
		CorrelationData: p.CorrelationData,
		MessageExpiry:   p.MessageExpiry,
		PayloadFormat:   p.PayloadFormat,
		UserProperties:  fromV5User(p.User),
		TopicAlias:      p.TopicAlias,
	}
	if p.SubscriptionIdentifier != nil {
		out.SubscriptionIDs = []int{*p.SubscriptionIdentifier}
	}
	if out.IsZero() {
		return nil
	}
	return out
}

func connackV5(ca *paho.Connack) *Connack {
	if ca == nil {
		return nil
	}
	out := &Connack{ReasonCode: ca.ReasonCode, Reason: ReasonName(ca.ReasonCode), SessionPresent: ca.SessionPresent}
	if p := ca.Properties; p != nil {
		m := map[string]any{}
		if p.AssignedClientID != "" {
			m["assigned_client_identifier"] = p.AssignedClientID
		}
		if p.ReasonString != "" {
			m["reason_string"] = p.ReasonString
		}
		if p.ResponseInfo != "" {
			m["response_information"] = p.ResponseInfo
		}
		if p.ServerReference != "" {
			m["server_reference"] = p.ServerReference
		}
		if p.SessionExpiryInterval != nil {
			m["session_expiry_interval"] = *p.SessionExpiryInterval
		}
		if p.ServerKeepAlive != nil {
			m["server_keep_alive"] = *p.ServerKeepAlive
		}
		if p.ReceiveMaximum != nil {
			m["receive_maximum"] = *p.ReceiveMaximum
		}
		if p.MaximumPacketSize != nil {
			m["maximum_packet_size"] = *p.MaximumPacketSize
		}
		if p.TopicAliasMaximum != nil {
			m["topic_alias_maximum"] = *p.TopicAliasMaximum
		}
		if p.MaximumQoS != nil {
			m["maximum_qos"] = *p.MaximumQoS
		}
		if p.AuthMethod != "" {
			m["authentication_method"] = p.AuthMethod
		}
		m["retain_available"] = p.RetainAvailable
		m["wildcard_subscription_available"] = p.WildcardSubAvailable
		m["subscription_identifiers_available"] = p.SubIDAvailable
		m["shared_subscription_available"] = p.SharedSubAvailable
		if len(p.User) > 0 {
			m["user_properties"] = fromV5User(p.User)
		}
		out.Properties = m
	}
	return out
}

func connectV5(ctx context.Context, cfg Config) (Client, *Connack, error) {
	v := &v5Client{conn: newPacketConn(cfg.Conn), id: cfg.ClientID}
	lost := func(err error) {
		if v.closing.Load() {
			return
		}
		v.lostMu.Do(func() {
			if cfg.OnLost != nil {
				cfg.OnLost(err)
			}
		})
	}
	cc := paho.ClientConfig{
		ClientID:      cfg.ClientID,
		Conn:          v.conn,
		PacketTimeout: cfg.PacketTimeout,
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){
			func(pr paho.PublishReceived) (bool, error) {
				if cfg.OnMessage != nil && pr.Packet != nil {
					p := pr.Packet
					cfg.OnMessage(Message{
						Topic:    p.Topic,
						Payload:  p.Payload,
						QoS:      p.QoS,
						Retain:   p.Retain,
						Dup:      p.Duplicate(),
						PacketID: p.PacketID,
						Props:    fromV5PubProps(p.Properties),
					})
				}
				return true, nil
			},
		},
		OnClientError: func(err error) { lost(fmt.Errorf("connection lost: %w", err)) },
		OnServerDisconnect: func(d *paho.Disconnect) {
			msg := fmt.Sprintf("broker sent DISCONNECT: reason 0x%02x (%s)", d.ReasonCode, ReasonName(d.ReasonCode))
			if d.Properties != nil && d.Properties.ReasonString != "" {
				msg += ": " + d.Properties.ReasonString
			}
			lost(fmt.Errorf("%s", msg))
		},
	}
	v.c = paho.NewClient(cc)
	cp := &paho.Connect{
		ClientID:     cfg.ClientID,
		KeepAlive:    cfg.KeepAlive,
		CleanStart:   cfg.CleanStart,
		Username:     cfg.Username,
		UsernameFlag: cfg.Username != "",
		PasswordFlag: cfg.Password != "",
	}
	if cfg.Password != "" {
		cp.Password = []byte(cfg.Password)
	}
	if cfg.SessionExpiry != nil {
		cp.Properties = &paho.ConnectProperties{SessionExpiryInterval: cfg.SessionExpiry, RequestProblemInfo: true}
	}
	if w := cfg.Will; w != nil {
		cp.WillMessage = &paho.WillMessage{Topic: w.Topic, Payload: w.Payload, QoS: w.QoS, Retain: w.Retain}
		if !w.Props.IsZero() || w.DelayInterval != nil {
			wp := &paho.WillProperties{WillDelayInterval: w.DelayInterval}
			if p := w.Props; p != nil {
				wp.ContentType = p.ContentType
				wp.ResponseTopic = p.ResponseTopic
				wp.CorrelationData = p.CorrelationData
				wp.MessageExpiry = p.MessageExpiry
				wp.PayloadFormat = p.PayloadFormat
				wp.User = toV5User(p.UserProperties)
			}
			cp.WillProperties = wp
		}
	}
	ca, err := v.c.Connect(ctx, cp)
	connack := connackV5(ca)
	if err != nil {
		v.closing.Store(true)
		cfg.Conn.Close()
		if connack != nil && connack.ReasonCode >= 0x80 {
			msg := fmt.Sprintf("broker refused the connection: reason 0x%02x (%s)", connack.ReasonCode, connack.Reason)
			if rs, ok := connack.Properties["reason_string"]; ok {
				msg += fmt.Sprintf(": %v", rs)
			}
			return nil, connack, fmt.Errorf("%s", msg)
		}
		return nil, connack, fmt.Errorf("MQTT connect: %w", err)
	}
	if connack != nil && connack.Properties != nil {
		if id, ok := connack.Properties["assigned_client_identifier"].(string); ok && id != "" {
			v.id = id
		}
	}
	return v, connack, nil
}

func (v *v5Client) Version() int     { return V5 }
func (v *v5Client) ClientID() string { return v.id }

func (v *v5Client) Publish(ctx context.Context, m Message) (*PubAck, error) {
	p := &paho.Publish{QoS: m.QoS, Retain: m.Retain, Topic: m.Topic, Payload: m.Payload, Properties: toV5PubProps(m.Props)}
	v.conn.lastPubID.Store(0)
	resp, err := v.c.Publish(ctx, p)
	ack := &PubAck{PacketID: uint16(v.conn.lastPubID.Load())}
	switch m.QoS {
	case 0:
		ack.Kind = "none"
	case 1:
		ack.Kind = "PUBACK"
	default:
		ack.Kind = "PUBCOMP"
	}
	if resp == nil {
		if err != nil {
			return nil, fmt.Errorf("publish: %w", err)
		}
		ack.Reason = ReasonName(0)
		ack.OK = true
		return ack, nil
	}
	ack.ReasonCode = resp.ReasonCode
	ack.Reason = ReasonName(resp.ReasonCode)
	ack.OK = resp.ReasonCode < 0x80
	if m.QoS == 2 && !ack.OK {
		ack.Kind = "PUBREC"
	}
	if resp.Properties != nil {
		ack.ReasonString = resp.Properties.ReasonString
		ack.UserProperties = fromV5User(resp.Properties.User)
	}
	return ack, nil
}

func (v *v5Client) Subscribe(ctx context.Context, subs []Subscription) ([]SubResult, error) {
	s := &paho.Subscribe{}
	for _, sub := range subs {
		s.Subscriptions = append(s.Subscriptions, paho.SubscribeOptions{
			Topic:             sub.Filter,
			QoS:               sub.QoS,
			RetainHandling:    sub.RetainHandling,
			NoLocal:           sub.NoLocal,
			RetainAsPublished: sub.RetainAsPublished,
		})
	}
	sa, err := v.c.Subscribe(ctx, s)
	if sa == nil {
		if err == nil {
			err = fmt.Errorf("no SUBACK")
		}
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	out := make([]SubResult, 0, len(subs))
	for i, sub := range subs {
		code := byte(0x80)
		if i < len(sa.Reasons) {
			code = sa.Reasons[i]
		}
		out = append(out, subResult(sub, code, true))
	}
	return out, nil
}

func (v *v5Client) Disconnect(withWill bool) {
	v.closing.Store(true)
	code := byte(0)
	if withWill {
		code = 0x04
	}
	_ = v.c.Disconnect(&paho.Disconnect{ReasonCode: code})
	select {
	case <-v.c.Done():
	case <-time.After(2 * time.Second):
	}
}
