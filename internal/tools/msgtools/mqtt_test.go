package msgtools_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/msgtools"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type broker struct {
	srv    *mqtt.Server
	tcp    string // tcp://127.0.0.1:port
	ws     string // ws://127.0.0.1:port/mqtt
	ssl    string // ssl://127.0.0.1:port
	caPEM  string
	inbox  chan packets.Packet
	inbMu  sync.Mutex
	inSubs map[string]bool
}

// authHook allows everything, or checks username/password when users is set.
type authHook struct {
	mqtt.HookBase
	users map[string]string
}

func (h *authHook) ID() string { return "netkit-test-auth" }

func (h *authHook) Provides(b byte) bool {
	return b == mqtt.OnConnectAuthenticate || b == mqtt.OnACLCheck
}

func (h *authHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	if h.users == nil {
		return true
	}
	p, ok := h.users[string(pk.Connect.Username)]
	return ok && p == string(pk.Connect.Password)
}

func (h *authHook) OnACLCheck(*mqtt.Client, string, bool) bool { return true }

type brokerOpts struct {
	users map[string]string // username -> password; nil = allow all
}

func startBroker(t *testing.T, o brokerOpts) *broker {
	t.Helper()
	srv := mqtt.New(&mqtt.Options{InlineClient: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := srv.AddHook(&authHook{users: o.users}, nil); err != nil {
		t.Fatal(err)
	}
	tcp := listeners.NewTCP(listeners.Config{ID: "tcp", Address: "127.0.0.1:0"})
	if err := srv.AddListener(tcp); err != nil {
		t.Fatal(err)
	}
	wsAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := srv.AddListener(listeners.NewWebsocket(listeners.Config{ID: "ws", Address: wsAddr})); err != nil {
		t.Fatal(err)
	}
	cert, caPEM := testCert(t)
	tl := listeners.NewTCP(listeners.Config{ID: "tls", Address: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err := srv.AddListener(tl); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Close() })
	b := &broker{srv: srv, tcp: "tcp://" + tcp.Address(), ws: "ws://" + wsAddr + "/mqtt", ssl: "ssl://" + tl.Address(),
		caPEM: caPEM, inbox: make(chan packets.Packet, 100), inSubs: map[string]bool{}}
	// Wait for the websocket listener to accept connections.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", wsAddr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return b
}

// watch subscribes the broker's inline client so tests can see what was
// published.
func (b *broker) watch(t *testing.T, filter string) {
	t.Helper()
	b.inbMu.Lock()
	defer b.inbMu.Unlock()
	if b.inSubs[filter] {
		return
	}
	b.inSubs[filter] = true
	if err := b.srv.Subscribe(filter, len(b.inSubs), func(_ *mqtt.Client, _ packets.Subscription, pk packets.Packet) {
		b.inbox <- pk
	}); err != nil {
		t.Fatal(err)
	}
}

func (b *broker) expect(t *testing.T, topic string) packets.Packet {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case pk := <-b.inbox:
			if pk.TopicName == topic {
				return pk
			}
		case <-timeout:
			t.Fatalf("broker did not receive a message on %q", topic)
		}
	}
}

// publishLoop publishes from the inline client until the returned stop func
// is called (for subscribe tests where the tool subscribes asynchronously).
func (b *broker) publishLoop(topic, payload string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = b.srv.Publish(topic, []byte(payload), false, 0)
			}
		}
	}()
	return func() { close(stop); <-done }
}

type pubOut struct {
	Broker          string `json:"broker"`
	ProtocolVersion string `json:"protocol_version"`
	ClientID        string `json:"client_id"`
	Connack         struct {
		ReasonCode byte   `json:"reason_code"`
		Reason     string `json:"reason"`
	} `json:"connack"`
	Published struct {
		Topic    string `json:"topic"`
		Bytes    int    `json:"bytes"`
		QoS      int    `json:"qos"`
		PacketID uint16 `json:"packet_id"`
	} `json:"published"`
	Ack struct {
		Kind       string `json:"kind"`
		PacketID   uint16 `json:"packet_id"`
		ReasonCode byte   `json:"reason_code"`
		OK         bool   `json:"ok"`
	} `json:"ack"`
	TLS *struct {
		Version            string `json:"version"`
		InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	} `json:"tls"`
	Warnings []string `json:"warnings"`
}

func TestMQTTPublishV5QoS1Properties(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "netkit/#")
	h := tooltest.New(t, "mqtt")
	r := h.MustOK("mqtt_publish", map[string]any{
		"broker":  b.tcp,
		"topic":   "netkit/v5",
		"payload": map[string]any{"json": map[string]any{"temp": 21.5}},
		"qos":     1,
		"properties": map[string]any{
			"content_type":     "application/json",
			"response_topic":   "netkit/reply",
			"correlation_data": "abc-123",
			"user_properties":  map[string]string{"source": "netkit", "unit": "C"},
		},
	})
	var out pubOut
	r.Decode(t, &out)
	if out.ProtocolVersion != "5" || out.Connack.ReasonCode != 0 || out.Ack.Kind != "PUBACK" || !out.Ack.OK {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	if out.Published.PacketID == 0 || out.Ack.PacketID != out.Published.PacketID {
		t.Fatalf("expected a packet id for QoS 1: %s", r.Raw)
	}
	pk := b.expect(t, "netkit/v5")
	if string(pk.Payload) != `{"temp":21.5}` {
		t.Fatalf("payload = %q", pk.Payload)
	}
	if pk.Properties.ContentType != "application/json" || pk.Properties.ResponseTopic != "netkit/reply" || string(pk.Properties.CorrelationData) != "abc-123" {
		t.Fatalf("properties not delivered: %+v", pk.Properties)
	}
	users := map[string]string{}
	for _, u := range pk.Properties.User {
		users[u.Key] = u.Val
	}
	if users["source"] != "netkit" || users["unit"] != "C" {
		t.Fatalf("user properties = %+v", pk.Properties.User)
	}
}

func TestMQTTPublishV311QoS2(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "netkit/#")
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"3.1.1", "4"} {
		r := h.MustOK("mqtt_publish", map[string]any{
			"broker":           b.tcp,
			"protocol_version": ver,
			"topic":            "netkit/v3",
			"payload":          map[string]any{"text": "hello " + ver},
			"qos":              2,
			"properties":       map[string]any{"content_type": "text/plain"},
		})
		var out pubOut
		r.Decode(t, &out)
		if out.ProtocolVersion != "3.1.1" || out.Ack.Kind != "PUBCOMP" || out.Published.PacketID == 0 {
			t.Fatalf("unexpected result: %s", r.Raw)
		}
		if len(out.Warnings) == 0 {
			t.Fatalf("expected a warning about ignored MQTT 5 properties: %s", r.Raw)
		}
		pk := b.expect(t, "netkit/v3")
		if string(pk.Payload) != "hello "+ver {
			t.Fatalf("payload = %q", pk.Payload)
		}
	}
}

func TestMQTTFilePayload(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "files/#")
	h := tooltest.New(t, "mqtt")
	data := []byte{0, 1, 2, 3, 0xff, 0xfe}
	p := h.WriteInput("blob.bin", data)
	r := h.MustOK("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "files/blob", "payload": map[string]any{"file": p}})
	var out struct {
		Published struct {
			Bytes       int `json:"bytes"`
			PayloadFile struct {
				SHA256 string `json:"sha256"`
			} `json:"payload_file"`
		} `json:"published"`
	}
	r.Decode(t, &out)
	if out.Published.Bytes != len(data) || out.Published.PayloadFile.SHA256 == "" {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
	pk := b.expect(t, "files/blob")
	if string(pk.Payload) != string(data) {
		t.Fatalf("payload = %v", pk.Payload)
	}
}

func TestMQTTRetainedSubscribe(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"5", "3.1.1"} {
		t.Run(ver, func(t *testing.T) {
			topic := "retained/" + ver
			h.MustOK("mqtt_publish", map[string]any{"broker": b.tcp, "protocol_version": ver, "topic": topic, "payload": map[string]any{"text": "keep me"}, "retain": true, "qos": 1})
			r := h.MustOK("mqtt_subscribe", map[string]any{"broker": b.tcp, "protocol_version": ver, "topic": topic, "qos": 1, "max_messages": 1, "max_duration_seconds": 5})
			var res types.StreamResult
			r.Decode(t, &res)
			in := inMessages(res)
			if res.EndedBy != types.EndedMaxMessages || len(in) != 1 {
				t.Fatalf("unexpected result: %s", r.Raw)
			}
			if in[0].Topic != topic || in[0].Data != "keep me" || in[0].Meta["retain"] != true {
				t.Fatalf("unexpected message: %+v", in[0])
			}
		})
	}
}

func TestMQTTSubscribeWildcardsPublishFirst(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"5", "3.1.1"} {
		t.Run(ver, func(t *testing.T) {
			r := h.MustOK("mqtt_subscribe", map[string]any{
				"broker":           b.tcp,
				"protocol_version": ver,
				"topics": []map[string]any{
					{"filter": "req/+/status", "qos": 2},
					{"filter": "other/#"},
				},
				"publish_first": map[string]any{
					"topic":   "req/dev1/status",
					"payload": map[string]any{"text": "ping"},
					"qos":     2,
					"properties": map[string]any{
						"response_topic":  "resp/dev1",
						"user_properties": map[string]string{"k": "v"},
					},
				},
				"max_messages":         1,
				"max_duration_seconds": 5,
			})
			var res types.StreamResult
			r.Decode(t, &res)
			in := inMessages(res)
			if len(in) != 1 || in[0].Topic != "req/dev1/status" || in[0].Data != "ping" {
				t.Fatalf("unexpected result: %s", r.Raw)
			}
			if q, _ := in[0].Meta["qos"].(float64); q != 2 {
				t.Fatalf("expected QoS 2 delivery, got %v", in[0].Meta["qos"])
			}
			if len(res.Messages) != 2 || res.Messages[0].Dir != "out" {
				t.Fatalf("expected the publish_first message recorded first: %s", r.Raw)
			}
			subs, _ := res.Meta["subscriptions"].([]any)
			if len(subs) != 2 {
				t.Fatalf("expected 2 subscription results: %v", res.Meta)
			}
			if ver == "5" {
				props, _ := in[0].Meta["properties"].(map[string]any)
				if props["response_topic"] != "resp/dev1" {
					t.Fatalf("expected MQTT 5 properties on the received message: %+v", in[0].Meta)
				}
			}
		})
	}
}

func TestMQTTSharedSubscription(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	stop := b.publishLoop("shared/topic", "tick")
	defer stop()
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"5", "3.1.1"} {
		t.Run(ver, func(t *testing.T) {
			r := h.MustOK("mqtt_subscribe", map[string]any{
				"broker": b.tcp, "protocol_version": ver, "topic": "$share/grp/shared/+",
				"max_messages": 2, "max_duration_seconds": 5,
			})
			var res types.StreamResult
			r.Decode(t, &res)
			in := inMessages(res)
			if res.EndedBy != types.EndedMaxMessages || len(in) != 2 || in[0].Topic != "shared/topic" || in[0].Data != "tick" {
				t.Fatalf("unexpected result: %s", r.Raw)
			}
		})
	}
}

func TestMQTTMaxDurationAndNoLocal(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	h := tooltest.New(t, "mqtt")
	// no_local: the publish_first message must not come back.
	r := h.MustOK("mqtt_subscribe", map[string]any{
		"broker":               b.tcp,
		"topics":               []map[string]any{{"filter": "loop/t", "no_local": true}},
		"publish_first":        map[string]any{"topic": "loop/t", "payload": map[string]any{"text": "x"}},
		"max_duration_seconds": 0.7,
	})
	var res types.StreamResult
	r.Decode(t, &res)
	if res.EndedBy != types.EndedMaxDuration || len(inMessages(res)) != 0 {
		t.Fatalf("unexpected result: %s", r.Raw)
	}
}

func TestMQTTWill(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "will/#")
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"5", "3.1.1"} {
		topic := "will/" + ver
		r := h.MustOK("mqtt_publish", map[string]any{
			"broker": b.tcp, "protocol_version": ver, "topic": "alive/" + ver, "payload": map[string]any{"text": "up"},
			"will":                 map[string]any{"topic": topic, "payload": map[string]any{"text": "gone"}, "qos": 1},
			"disconnect_with_will": true,
		})
		_ = r
		pk := b.expect(t, topic)
		if string(pk.Payload) != "gone" {
			t.Fatalf("will payload = %q", pk.Payload)
		}
	}
	// A normal disconnect must not trigger the will.
	h.MustOK("mqtt_publish", map[string]any{
		"broker": b.tcp, "topic": "alive/x", "payload": map[string]any{"text": "up"},
		"will": map[string]any{"topic": "will/never", "payload": map[string]any{"text": "gone"}},
	})
	select {
	case pk := <-b.inbox:
		if pk.TopicName == "will/never" {
			t.Fatal("will published after a normal disconnect")
		}
	case <-time.After(300 * time.Millisecond):
	}
}

func TestMQTTAuth(t *testing.T) {
	b := startBroker(t, brokerOpts{users: map[string]string{"alice": "s3cret"}})
	h := tooltest.New(t, "mqtt")
	h.MustOK("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "a/b", "auth": map[string]any{"type": "basic", "username": "alice", "password": "s3cret"}})
	h.MustOK("mqtt_publish", map[string]any{"broker": b.tcp, "protocol_version": "3.1.1", "topic": "a/b", "username": "alice", "password": "s3cret"})
	r := h.MustFail("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "a/b", "username": "alice", "password": "wrong"}, "refused")
	mustContain(t, r.Text, "0x86")
	for _, s := range []string{"wrong", "s3cret"} {
		if strings.Contains(r.Text, s) {
			t.Fatalf("error leaks the password: %s", r.Text)
		}
	}
	h.MustFail("mqtt_publish", map[string]any{"broker": b.tcp, "protocol_version": "3.1.1", "topic": "a/b", "username": "alice", "password": "wrong"}, "refused")
	h.MustFail("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "a/b", "auth": map[string]any{"type": "api_key", "key": "x", "value": "y"}}, "not supported for MQTT")
}

func TestMQTTWebSocket(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "ws/#")
	h := tooltest.New(t, "mqtt")
	for _, ver := range []string{"5", "3.1.1"} {
		h.MustOK("mqtt_publish", map[string]any{"broker": b.ws, "protocol_version": ver, "topic": "ws/" + ver, "payload": map[string]any{"text": "over ws"}, "qos": 1})
		pk := b.expect(t, "ws/"+ver)
		if string(pk.Payload) != "over ws" {
			t.Fatalf("payload = %q", pk.Payload)
		}
		r := h.MustOK("mqtt_subscribe", map[string]any{
			"broker": b.ws, "protocol_version": ver, "topic": "wsq/#",
			"publish_first": map[string]any{"topic": "wsq/echo", "payload": map[string]any{"base64": "AAEC"}, "qos": 1},
			"max_messages":  1, "max_duration_seconds": 5,
		})
		var res types.StreamResult
		r.Decode(t, &res)
		in := inMessages(res)
		if len(in) != 1 || in[0].Encoding != "base64" || in[0].Data != "AAEC" {
			t.Fatalf("unexpected result: %s", r.Raw)
		}
	}
}

func TestMQTTTLS(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	b.watch(t, "tls/#")
	h := tooltest.New(t, "mqtt")
	r := h.MustOK("mqtt_publish", map[string]any{"broker": b.ssl, "topic": "tls/ca", "payload": map[string]any{"text": "secure"}, "ca_cert": b.caPEM, "qos": 1})
	var out pubOut
	r.Decode(t, &out)
	if out.TLS == nil || out.TLS.Version == "" {
		t.Fatalf("expected TLS info: %s", r.Raw)
	}
	b.expect(t, "tls/ca")
	// insecure_skip_verify works and is flagged.
	r = h.MustOK("mqtt_publish", map[string]any{"broker": b.ssl, "protocol_version": "3.1.1", "topic": "tls/insecure", "insecure_skip_verify": true})
	r.Decode(t, &out)
	if out.TLS == nil || !out.TLS.InsecureSkipVerify || len(out.Warnings) == 0 {
		t.Fatalf("insecure_skip_verify not flagged: %s", r.Raw)
	}
	b.expect(t, "tls/insecure")
	// Without the CA the handshake fails.
	h.MustFail("mqtt_publish", map[string]any{"broker": b.ssl, "topic": "tls/x"}, "TLS handshake")
}

func TestMQTTValidation(t *testing.T) {
	h := tooltest.New(t, "mqtt")
	h.MustFail("mqtt_publish", map[string]any{"broker": "tcp://127.0.0.1:1", "topic": "a/+"}, "wildcard")
	h.MustFail("mqtt_publish", map[string]any{"broker": "tcp://127.0.0.1:1", "topic": "a", "qos": 3}, "qos")
	h.MustFail("mqtt_publish", map[string]any{"broker": "tcp://127.0.0.1:1", "topic": "a", "protocol_version": "6"}, "protocol_version")
	h.MustFail("mqtt_publish", map[string]any{"broker": "http://127.0.0.1:1", "topic": "a"}, "unsupported broker scheme")
	h.MustFail("mqtt_subscribe", map[string]any{"broker": "tcp://127.0.0.1:1", "topic": "a/#/b"}, "'#'")
	h.MustFail("mqtt_subscribe", map[string]any{"broker": "tcp://127.0.0.1:1"}, "topic")
}

func TestMQTTSSRFBlocked(t *testing.T) {
	b := startBroker(t, brokerOpts{})
	h := tooltest.New(t, "mqtt", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "x"}, "blocked")
	h.MustFail("mqtt_publish", map[string]any{"broker": b.ws, "topic": "x"}, "blocked")
	h.MustFail("mqtt_subscribe", map[string]any{"broker": b.ssl, "topic": "x", "ca_cert": b.caPEM}, "blocked")
	h.MustFail("mqtt_publish", map[string]any{"broker": "tcp://localhost:1883", "topic": "x"}, "blocked")
	// Opting in per call works under PrivateOptIn.
	h.MustOK("mqtt_publish", map[string]any{"broker": b.tcp, "topic": "x", "allow_private": true})
}
