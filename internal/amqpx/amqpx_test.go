package amqpx_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/HamedFathi/NetKitMCP/internal/amqpx"
	"github.com/HamedFathi/NetKitMCP/internal/amqpx/amqpfake"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
)

func dialer(mode config.PrivateMode, allow bool) *netguard.Dialer {
	cfg := config.Default()
	cfg.PrivateMode = mode
	return netguard.New(cfg).Dialer(allow, 5*time.Second)
}

func TestToTableAndBack(t *testing.T) {
	tab, err := amqpx.ToTable(map[string]any{
		"i": float64(5), "big": float64(1 << 40), "f": 1.5, "s": "x", "b": true,
		"nested": map[string]any{"k": float64(1)}, "arr": []any{"a", float64(2)}, "nil": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tab["i"] != int32(5) || tab["big"] != int64(1<<40) || tab["f"] != 1.5 {
		t.Fatalf("numbers: %#v", tab)
	}
	if _, ok := tab["nested"].(amqp.Table); !ok {
		t.Fatalf("nested: %T", tab["nested"])
	}
	if err := tab.Validate(); err != nil {
		t.Fatal(err)
	}
	back := amqpx.FromTable(amqp.Table{"bytes": []byte{1, 2}, "dec": amqp.Decimal{Scale: 2, Value: 12345}, "ts": time.Unix(0, 0)})
	if back["bytes"] != "AQI=" || math.Abs(back["dec"].(float64)-123.45) > 1e-9 || back["ts"] != "1970-01-01T00:00:00Z" {
		t.Fatalf("from table: %#v", back)
	}
	if _, err := amqpx.ToTable(map[string]any{"bad": struct{}{}}); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestPublishingProperties(t *testing.T) {
	p := &amqpx.Properties{Persistent: true, Priority: 5, Expiration: "1000", Timestamp: "1700000000", Headers: map[string]any{"a": "b"}}
	pub, err := p.Publishing([]byte("x"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if pub.DeliveryMode != 2 || pub.Priority != 5 || pub.ContentType != "text/plain" || pub.Timestamp.Unix() != 1700000000 || pub.Headers["a"] != "b" {
		t.Fatalf("%+v", pub)
	}
	for _, bad := range []amqpx.Properties{{Expiration: "soon"}, {DeliveryMode: 3}, {Timestamp: "yesterday"}} {
		if _, err := bad.Publishing(nil, ""); err == nil {
			t.Fatalf("expected error for %+v", bad)
		}
	}
}

func TestFakeBrokerRoundTrip(t *testing.T) {
	b, err := amqpfake.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	conn, err := amqpx.Dial(ctx, b.URL()+"vh1", amqpx.DialOptions{Dialer: dialer(config.PrivateAllow, false), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&amqpx.Declare{
		Exchange: &amqpx.ExchangeDecl{Name: "ex", Type: "topic"},
		Queue:    &amqpx.QueueDecl{Name: "q1"},
		Bindings: []amqpx.BindingDecl{{Exchange: "ex", RoutingKey: "a.#"}},
	}).Apply(ch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Queue.Name != "q1" || res.Bindings != 1 {
		t.Fatalf("%+v", res)
	}
	if err := ch.Confirm(false); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("z", 300000) // spans several frames
	dc, err := ch.PublishWithDeferredConfirm("ex", "a.b.c", false, false, amqp.Publishing{ContentType: "text/plain", Headers: amqp.Table{"h": "v"}, Body: []byte(big)})
	if err != nil {
		t.Fatal(err)
	}
	if !dc.Wait() {
		t.Fatal("nacked")
	}
	d, ok, err := ch.Get("q1", false)
	if err != nil || !ok {
		t.Fatalf("get: %v %v", ok, err)
	}
	if string(d.Body) != big || d.ContentType != "text/plain" || d.Headers["h"] != "v" || d.RoutingKey != "a.b.c" {
		t.Fatalf("delivery mismatch: ct=%q headers=%v rk=%q len=%d", d.ContentType, d.Headers, d.RoutingKey, len(d.Body))
	}
	if err := d.Reject(true); err != nil {
		t.Fatal(err)
	}
	msgs, err := ch.Consume("q1", "", false, false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-msgs:
		if !m.Redelivered {
			t.Fatal("expected redelivered")
		}
		m.Ack(false)
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery")
	}
	if got := b.Vhosts(); len(got) != 1 || got[0] != "vh1" {
		t.Fatalf("vhosts %v", got)
	}
}

func TestDialAuthAndGuard(t *testing.T) {
	b, err := amqpfake.Start(amqpfake.WithUsers(map[string]string{"u": "p"}))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	_, err = amqpx.Dial(ctx, b.URL(), amqpx.DialOptions{Dialer: dialer(config.PrivateAllow, false), Timeout: 5 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "authentication") && !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected auth failure, got %v", err)
	}
	conn, err := amqpx.Dial(ctx, b.URL(), amqpx.DialOptions{Dialer: dialer(config.PrivateAllow, false), Username: "u", Password: "p", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	_, err = amqpx.Dial(ctx, b.URL(), amqpx.DialOptions{Dialer: dialer(config.PrivateOptIn, false), Timeout: 5 * time.Second})
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("expected guard block, got %v", err)
	}
	if _, err := amqpx.ParseURL("http://x"); err == nil {
		t.Fatal("expected scheme error")
	}
}
