package mqttx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type v3Client struct {
	c       mqtt.Client
	conn    net.Conn
	id      string
	version int
	closing atomic.Bool
}

// waitToken waits for a paho.mqtt.golang token or the context.
func waitToken(ctx context.Context, t mqtt.Token) error {
	select {
	case <-t.Done():
		return t.Error()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func connectV3(ctx context.Context, cfg Config) (Client, *Connack, error) {
	v := &v3Client{conn: cfg.Conn, id: cfg.ClientID, version: cfg.Version}
	var lostOnce sync.Once
	lost := func(err error) {
		if v.closing.Load() {
			return
		}
		lostOnce.Do(func() {
			if cfg.OnLost != nil {
				cfg.OnLost(err)
			}
		})
	}
	var used atomic.Bool
	timeout := cfg.PacketTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	opts := mqtt.NewClientOptions()
	// The broker URL is only a label: the connection is supplied below.
	opts.AddBroker("tcp://" + cfg.Conn.RemoteAddr().String())
	opts.SetCustomOpenConnectionFn(func(*url.URL, mqtt.ClientOptions) (net.Conn, error) {
		if used.Swap(true) {
			return nil, errors.New("reconnect is disabled")
		}
		return cfg.Conn, nil
	})
	opts.SetClientID(cfg.ClientID)
	opts.SetCleanSession(cfg.CleanStart)
	opts.SetKeepAlive(time.Duration(cfg.KeepAlive) * time.Second)
	opts.SetPingTimeout(cfg.PacketTimeout)
	opts.SetProtocolVersion(uint(cfg.Version))
	opts.SetAutoReconnect(false)
	opts.SetConnectRetry(false)
	opts.SetResumeSubs(false)
	opts.SetConnectTimeout(timeout)
	opts.SetWriteTimeout(cfg.PacketTimeout)
	opts.SetOrderMatters(true)
	if cfg.Username != "" {
		opts.SetUsername(cfg.Username)
	}
	if cfg.Password != "" {
		opts.SetPassword(cfg.Password)
	}
	if w := cfg.Will; w != nil {
		opts.SetBinaryWill(w.Topic, w.Payload, w.QoS, w.Retain)
	}
	opts.SetDefaultPublishHandler(func(_ mqtt.Client, m mqtt.Message) {
		if cfg.OnMessage != nil {
			cfg.OnMessage(Message{
				Topic:    m.Topic(),
				Payload:  m.Payload(),
				QoS:      m.Qos(),
				Retain:   m.Retained(),
				Dup:      m.Duplicate(),
				PacketID: m.MessageID(),
			})
		}
	})
	opts.SetConnectionLostHandler(func(_ mqtt.Client, err error) {
		lost(fmt.Errorf("connection lost: %w", err))
	})
	v.c = mqtt.NewClient(opts)
	tok := v.c.Connect()
	err := waitToken(ctx, tok)
	var connack *Connack
	if ct, ok := tok.(*mqtt.ConnectToken); ok {
		select {
		case <-tok.Done():
			rc := ct.ReturnCode()
			connack = &Connack{ReasonCode: rc, Reason: V3ConnackName(rc), SessionPresent: ct.SessionPresent()}
		default:
		}
	}
	if err != nil {
		v.closing.Store(true)
		cfg.Conn.Close()
		v.c.Disconnect(0)
		if connack != nil && connack.ReasonCode != 0 {
			return nil, connack, fmt.Errorf("broker refused the connection: %s", connack.Reason)
		}
		return nil, connack, fmt.Errorf("MQTT connect: %w", err)
	}
	return v, connack, nil
}

func (v *v3Client) Version() int     { return v.version }
func (v *v3Client) ClientID() string { return v.id }

func (v *v3Client) Publish(ctx context.Context, m Message) (*PubAck, error) {
	tok := v.c.Publish(m.Topic, m.QoS, m.Retain, m.Payload)
	if err := waitToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}
	ack := &PubAck{Reason: "Success", OK: true}
	if pt, ok := tok.(*mqtt.PublishToken); ok {
		ack.PacketID = pt.MessageID()
	}
	switch m.QoS {
	case 0:
		ack.Kind = "none"
	case 1:
		ack.Kind = "PUBACK"
	default:
		ack.Kind = "PUBCOMP"
	}
	return ack, nil
}

func (v *v3Client) Subscribe(ctx context.Context, subs []Subscription) ([]SubResult, error) {
	filters := make(map[string]byte, len(subs))
	for _, s := range subs {
		filters[s.Filter] = s.QoS
	}
	tok := v.c.SubscribeMultiple(filters, nil)
	if err := waitToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	var granted map[string]byte
	if st, ok := tok.(*mqtt.SubscribeToken); ok {
		granted = st.Result()
	}
	out := make([]SubResult, 0, len(subs))
	for _, s := range subs {
		code, ok := granted[s.Filter]
		if !ok {
			code = 0x80
		}
		out = append(out, subResult(s, code, false))
	}
	return out, nil
}

func (v *v3Client) Disconnect(withWill bool) {
	v.closing.Store(true)
	if withWill {
		// MQTT 3.1.x has no "disconnect with will": drop the connection
		// without DISCONNECT so the broker publishes the will.
		v.conn.Close()
		v.c.Disconnect(0)
		return
	}
	v.c.Disconnect(250)
}
