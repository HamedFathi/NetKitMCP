package brokertools_test

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/amqpx/amqpfake"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func startAMQP(t *testing.T, opts ...amqpfake.Option) *amqpfake.Broker {
	t.Helper()
	b, err := amqpfake.Start(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestAMQPPublishConsumeRoundTrip(t *testing.T) {
	b := startAMQP(t)
	h := tooltest.New(t, "messaging")

	r := h.MustOK("amqp_publish", map[string]any{
		"url":         b.URL() + "vh1",
		"routing_key": "orders",
		"payload":     map[string]any{"json": map[string]any{"id": 7}},
		"properties": map[string]any{
			"persistent": true, "message_id": "m-1", "correlation_id": "c-1", "timestamp": "1700000000",
			"headers": map[string]any{"tenant": "acme", "attempt": 2},
		},
		"declare": map[string]any{"queue": map[string]any{"name": "orders", "durable": true}},
	})
	if r.Data["confirm"] != "ack" || r.Data["size_bytes"].(float64) != 8 {
		t.Fatalf("publish result: %s", r.Raw)
	}
	if q := r.Data["declared"].(map[string]any)["queue"].(map[string]any); q["name"] != "orders" {
		t.Fatalf("declared: %v", q)
	}
	if strings.Contains(r.Data["target"].(string), "guest:guest") {
		t.Fatalf("password not redacted: %v", r.Data["target"])
	}
	if b.QueueLen("orders") != 1 {
		t.Fatalf("queue len %d", b.QueueLen("orders"))
	}

	res := stream(t, h.MustOK("amqp_consume", map[string]any{"url": b.URL(), "queue": "orders", "max_messages": 1}))
	if res.EndedBy != "max_messages" || len(res.Messages) != 1 {
		t.Fatalf("consume: %+v", res)
	}
	m := res.Messages[0]
	if m.Data != `{"id":7}` || m.Encoding != "text" || m.ID != "m-1" || m.Topic != "orders" {
		t.Fatalf("message: %+v", m)
	}
	props := m.Meta["properties"].(map[string]any)
	if props["content_type"] != "application/json" || props["delivery_mode"].(float64) != 2 || props["correlation_id"] != "c-1" ||
		props["timestamp"] != "2023-11-14T22:13:20Z" {
		t.Fatalf("properties: %v", props)
	}
	hdr := props["headers"].(map[string]any)
	if hdr["tenant"] != "acme" || hdr["attempt"].(float64) != 2 {
		t.Fatalf("headers: %v", hdr)
	}
	if res.Meta["settled"].(float64) != 1 || b.QueueLen("orders") != 0 {
		t.Fatalf("expected ack; meta=%v len=%d", res.Meta, b.QueueLen("orders"))
	}
	if v := b.Vhosts(); v[0] != "vh1" {
		t.Fatalf("vhost: %v", v)
	}
}

func TestAMQPPublishFileAndBinary(t *testing.T) {
	b := startAMQP(t)
	b.DeclareQueue("bin")
	h := tooltest.New(t, "messaging")
	p := h.WriteInput("blob.bin", []byte{0, 1, 2, 0xff})
	r := h.MustOK("amqp_publish", map[string]any{"url": b.URL(), "routing_key": "bin", "payload": map[string]any{"file": p}})
	if r.Data["file"].(map[string]any)["size_bytes"].(float64) != 4 {
		t.Fatalf("%s", r.Raw)
	}
	res := stream(t, h.MustOK("amqp_consume", map[string]any{"url": b.URL(), "queue": "bin", "mode": "get"}))
	if len(res.Messages) != 1 || res.Messages[0].Encoding != "base64" || res.Messages[0].Data != "AAEC/w==" || res.EndedBy != "complete" {
		t.Fatalf("%+v", res)
	}
}

func TestAMQPMandatoryReturnAndNack(t *testing.T) {
	b := startAMQP(t, amqpfake.WithNackExchange("nackex"))
	h := tooltest.New(t, "messaging")
	r := h.MustOK("amqp_publish", map[string]any{
		"url": b.URL(), "exchange": "amq.direct", "routing_key": "nowhere", "mandatory": true,
		"payload": map[string]any{"text": "lost"},
	})
	ret, ok := r.Data["returned"].(map[string]any)
	if !ok || ret["reply_code"].(float64) != 312 || ret["reply_text"] != "NO_ROUTE" || r.Data["routed"] != false {
		t.Fatalf("expected return: %s", r.Raw)
	}
	r = h.MustOK("amqp_publish", map[string]any{
		"url": b.URL(), "exchange": "nackex", "payload": map[string]any{"text": "x"},
		"declare": map[string]any{"exchange": map[string]any{"name": "nackex", "type": "fanout"}},
	})
	if r.Data["confirm"] != "nack" {
		t.Fatalf("expected nack: %s", r.Raw)
	}
	h.MustFail("amqp_publish", map[string]any{"url": b.URL(), "exchange": "missing", "payload": map[string]any{"text": "x"}}, "NOT_FOUND")
	r = h.MustOK("amqp_publish", map[string]any{"url": b.URL(), "routing_key": "q", "confirm": false, "payload": map[string]any{"text": "x"}})
	if r.Data["confirm"] != "disabled" {
		t.Fatalf("%s", r.Raw)
	}
}

func TestAMQPAckModes(t *testing.T) {
	b := startAMQP(t)
	b.DeclareQueue("work")
	for i := 0; i < 5; i++ {
		if _, err := b.Publish("", "work", []byte(fmt.Sprintf("job-%d", i)), "text/plain", map[string]string{"n": fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	h := tooltest.New(t, "messaging")
	url := b.URL()

	// requeue (peek) with basic.get leaves everything on the queue.
	res := stream(t, h.MustOK("amqp_consume", map[string]any{"url": url, "queue": "work", "mode": "get", "ack_mode": "requeue"}))
	if len(res.Messages) != 5 || res.EndedBy != "complete" || res.Messages[4].Meta["message_count"].(float64) != 0 {
		t.Fatalf("peek: %+v", res)
	}
	waitLen(t, b, "work", 5)

	// ack with a limit: only the collected messages are removed.
	res = stream(t, h.MustOK("amqp_consume", map[string]any{"url": url, "queue": "work", "max_messages": 2}))
	if len(res.Messages) != 2 || res.Messages[0].Data != "job-0" || res.Messages[0].Meta["redelivered"] != true {
		t.Fatalf("ack: %+v", res)
	}
	waitLen(t, b, "work", 3)

	// reject drops one.
	res = stream(t, h.MustOK("amqp_consume", map[string]any{"url": url, "queue": "work", "max_messages": 1, "ack_mode": "reject"}))
	if len(res.Messages) != 1 || res.Messages[0].Data != "job-2" {
		t.Fatalf("reject: %+v", res)
	}
	waitLen(t, b, "work", 2)

	// none = auto-ack; idle timeout ends the call once the queue is drained.
	res = stream(t, h.MustOK("amqp_consume", map[string]any{"url": url, "queue": "work", "ack_mode": "none", "idle_timeout_seconds": 0.5}))
	if len(res.Messages) != 2 || res.EndedBy != "idle" {
		t.Fatalf("none: %+v", res)
	}
	waitLen(t, b, "work", 0)

	h.MustFail("amqp_consume", map[string]any{"url": url, "queue": "nope", "max_duration_seconds": 1}, "NOT_FOUND")
	h.MustFail("amqp_consume", map[string]any{"url": url, "queue": "work", "ack_mode": "bogus"}, "ack_mode")
	h.MustFail("amqp_consume", map[string]any{"url": url}, "queue is required")
}

func waitLen(t *testing.T, b *amqpfake.Broker, q string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for b.QueueLen(q) != want {
		if time.Now().After(deadline) {
			t.Fatalf("queue %s: len %d, want %d", q, b.QueueLen(q), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAMQPConsumeTemporaryQueue(t *testing.T) {
	b := startAMQP(t)
	h := tooltest.New(t, "messaging")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent := 0
		for deadline := time.Now().Add(5 * time.Second); sent < 2 && time.Now().Before(deadline); {
			routed, _ := b.Publish("amq.topic", "logs.app.error", []byte(fmt.Sprintf("line %d", sent)), "text/plain", nil)
			if routed {
				sent++
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
		b.Publish("amq.topic", "metrics.cpu", []byte("ignored"), "", nil)
	}()
	res := stream(t, h.MustOK("amqp_consume", map[string]any{
		"url": b.URL(), "exchange": "amq.topic", "routing_key": "logs.#", "max_messages": 2, "max_duration_seconds": 5,
	}))
	wg.Wait()
	if len(res.Messages) != 2 || res.Meta["temporary"] != true || !strings.HasPrefix(res.Meta["queue"].(string), "amq.gen-") {
		t.Fatalf("%+v", res)
	}
	if res.Messages[0].Meta["routing_key"] != "logs.app.error" || res.Messages[0].Meta["exchange"] != "amq.topic" {
		t.Fatalf("%+v", res.Messages[0])
	}
}

func TestAMQPAuthAndTLS(t *testing.T) {
	srvTLS, caPEM := testTLS(t)
	b := startAMQP(t, amqpfake.WithUsers(map[string]string{"alice": "s3cret"}), amqpfake.WithTLS(srvTLS))
	h := tooltest.New(t, "messaging")
	url := "amqps://" + b.Addr() + "/"
	if !strings.HasPrefix(b.URL(), "amqps://") {
		t.Fatal("expected amqps")
	}
	h.MustFail("amqp_publish", map[string]any{"url": url, "routing_key": "q", "ca_cert": caPEM,
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "wrong"}}, "authentication")
	h.MustFail("amqp_publish", map[string]any{"url": url, "routing_key": "q",
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "s3cret"}}, "certificate")
	r := h.MustOK("amqp_publish", map[string]any{"url": url, "routing_key": "q", "ca_cert": caPEM,
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "s3cret"}})
	tlsInfo := r.Data["tls"].(map[string]any)
	if tlsInfo["version"] == "" {
		t.Fatalf("tls: %v", tlsInfo)
	}
	r = h.MustOK("amqp_publish", map[string]any{"url": "amqps://alice:s3cret@" + b.Addr() + "/", "routing_key": "q", "insecure_skip_verify": true})
	if len(r.Data["warnings"].([]any)) == 0 || r.Data["tls"].(map[string]any)["insecure_skip_verify"] != true {
		t.Fatalf("expected insecure warning: %s", r.Raw)
	}
}

func TestAMQPGuardBlocksPrivate(t *testing.T) {
	b := startAMQP(t)
	h := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("amqp_publish", map[string]any{"url": b.URL(), "routing_key": "q"}, "blocked")
	h.MustFail("amqp_consume", map[string]any{"url": b.URL(), "queue": "q"}, "blocked")
	h.MustFail("amqp_publish", map[string]any{"url": "amqp://localhost:5672/", "routing_key": "q"}, "blocked")
	h.MustOK("amqp_publish", map[string]any{"url": b.URL(), "routing_key": "q", "allow_private": true})
}

// TestAMQPRealBroker runs against a real broker when NETKIT_TEST_AMQP_URL is
// set (e.g. amqp://guest:guest@localhost:5672/).
func TestAMQPRealBroker(t *testing.T) {
	url := os.Getenv("NETKIT_TEST_AMQP_URL")
	if url == "" {
		t.Skip("NETKIT_TEST_AMQP_URL not set")
	}
	h := tooltest.New(t, "messaging")
	q := fmt.Sprintf("netkit-test-%d", time.Now().UnixNano())
	r := h.MustOK("amqp_publish", map[string]any{
		"url": url, "routing_key": q, "payload": map[string]any{"text": "hello"}, "mandatory": true,
		"properties": map[string]any{"headers": map[string]any{"k": "v"}},
		"declare":    map[string]any{"queue": map[string]any{"name": q, "auto_delete": false, "arguments": map[string]any{"x-expires": 60000}}},
	})
	if r.Data["confirm"] != "ack" || r.Data["routed"] != true {
		t.Fatalf("%s", r.Raw)
	}
	res := stream(t, h.MustOK("amqp_consume", map[string]any{"url": url, "queue": q, "max_messages": 1, "max_duration_seconds": 5}))
	if len(res.Messages) != 1 || res.Messages[0].Data != "hello" {
		t.Fatalf("%+v", res)
	}
}
