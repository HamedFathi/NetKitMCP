package brokertools_test

import (
	"fmt"
	"testing"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func startKafka(t *testing.T, opts ...kfake.Opt) []string {
	t.Helper()
	c, err := kfake.NewCluster(append([]kfake.Opt{kfake.NumBrokers(1), kfake.SeedTopics(3, "events", "other")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c.ListenAddrs()
}

func TestKafkaProduceConsume(t *testing.T) {
	brokers := startKafka(t)
	h := tooltest.New(t, "messaging")
	r := h.MustOK("kafka_produce", map[string]any{
		"brokers": brokers,
		"topic":   "events",
		"records": []any{
			map[string]any{"key": map[string]any{"text": "user-1"}, "value": map[string]any{"json": map[string]any{"a": 1}},
				"headers": map[string]string{"trace": "abc"}, "partition": 2},
			map[string]any{"key": map[string]any{"text": "user-2"}, "value": map[string]any{"text": "plain"}, "partition": 2},
			map[string]any{"value": map[string]any{"base64": "AAH/"}, "partition": 2, "timestamp": "1700000000000"},
			map[string]any{"key": map[string]any{"text": "tomb"}, "partition": 2},
		},
		"compression": "gzip",
	})
	var out struct {
		Produced, Failed int
		Idempotent       bool
		Results          []struct {
			Partition int32
			Offset    int64
			Timestamp string
			Error     string
		}
	}
	r.Decode(t, &out)
	if out.Produced != 4 || out.Failed != 0 || !out.Idempotent {
		t.Fatalf("produce: %s", r.Raw)
	}
	for i, res := range out.Results {
		if res.Partition != 2 || res.Offset != int64(i) {
			t.Fatalf("result %d: %+v", i, res)
		}
	}
	if out.Results[2].Timestamp != "2023-11-14T22:13:20Z" {
		t.Fatalf("timestamp: %+v", out.Results[2])
	}

	res := stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"}, "max_messages": 4}))
	if res.EndedBy != "max_messages" || len(res.Messages) != 4 {
		t.Fatalf("consume: %+v", res)
	}
	m := res.Messages[0]
	if m.Data != `{"a":1}` || m.Meta["key"] != "user-1" || m.Headers["trace"] != "abc" || m.Meta["partition"].(float64) != 2 ||
		m.Topic != "events" || m.ID != "events/2/0" {
		t.Fatalf("message 0: %+v", m)
	}
	if res.Messages[2].Encoding != "base64" || res.Messages[2].Data != "AAH/" || res.Messages[2].Meta["key"] != nil {
		t.Fatalf("message 2: %+v", res.Messages[2])
	}
	if res.Messages[3].Meta["null_value"] != true {
		t.Fatalf("tombstone: %+v", res.Messages[3])
	}

	// Exact offsets and tail.
	res = stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"},
		"partition_offsets": map[string]int64{"2": 3}, "idle_timeout_seconds": 1}))
	if len(res.Messages) != 1 || res.Messages[0].Meta["offset"].(float64) != 3 {
		t.Fatalf("partition_offsets: %+v", res)
	}
	res = stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"},
		"partitions": []int{2}, "start": "tail", "offset": 2, "idle_timeout_seconds": 1}))
	if len(res.Messages) != 2 || res.Messages[0].Meta["offset"].(float64) != 2 {
		t.Fatalf("tail: %+v", res)
	}
	res = stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"},
		"start": "latest", "max_duration_seconds": 1}))
	if len(res.Messages) != 0 || res.EndedBy != "max_duration" {
		t.Fatalf("latest: %+v", res)
	}
}

func TestKafkaGroupCommit(t *testing.T) {
	brokers := startKafka(t)
	h := tooltest.New(t, "messaging")
	var recs []any
	for i := 0; i < 6; i++ {
		recs = append(recs, map[string]any{"key": map[string]any{"text": fmt.Sprintf("k%d", i)}, "value": map[string]any{"text": fmt.Sprintf("v%d", i)}})
	}
	h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "other", "records": recs, "acks": "leader", "compression": "zstd"})

	args := map[string]any{"brokers": brokers, "topics": []string{"other"}, "group": "g1", "commit": true, "max_messages": 4, "max_duration_seconds": 10}
	res := stream(t, h.MustOK("kafka_consume", args))
	if len(res.Messages) != 4 || res.Meta["committed"] != true {
		t.Fatalf("first: %+v", res)
	}
	args["max_messages"] = 10
	args["idle_timeout_seconds"] = 2
	res = stream(t, h.MustOK("kafka_consume", args))
	if len(res.Messages) != 2 || res.Meta["committed"] != true {
		t.Fatalf("second (should resume after committed offsets): %+v", res)
	}
	h.MustFail("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"other"}, "commit": true}, "commit requires group")
	h.MustFail("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"other"}, "group": "g", "partitions": []int{0}}, "cannot be combined")
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "other", "records": []any{map[string]any{}}, "acks": "none", "idempotent": true}, "requires acks=all")
}

func TestKafkaProduceErrors(t *testing.T) {
	brokers := startKafka(t)
	h := tooltest.New(t, "messaging")
	r := h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events",
		"records": []any{map[string]any{"value": map[string]any{"text": "x"}, "partition": 9}}, "timeout_seconds": 5})
	if r.Data["failed"].(float64) != 1 {
		t.Fatalf("expected per-record failure: %s", r.Raw)
	}
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "records": []any{map[string]any{}}}, "topic is required")
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": []any{}}, "records is required")
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": []any{map[string]any{}}, "compression": "brotli"}, "compression")
}

func TestKafkaSASL(t *testing.T) {
	brokers := startKafka(t, kfake.EnableSASL(), kfake.Superuser("PLAIN", "alice", "pw"), kfake.Superuser("SCRAM-SHA-256", "bob", "pw2"),
		kfake.Superuser("SCRAM-SHA-512", "carol", "pw3"))
	h := tooltest.New(t, "messaging")
	rec := []any{map[string]any{"value": map[string]any{"text": "secret"}}}
	h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec,
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "pw"}})
	h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec,
		"sasl": map[string]any{"mechanism": "SCRAM-SHA-256", "username": "bob", "password": "pw2"}})
	h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec,
		"sasl": map[string]any{"mechanism": "SCRAM-SHA-512"}, "auth": map[string]any{"type": "basic", "username": "carol", "password": "pw3"}})
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec, "timeout_seconds": 5,
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "nope"}}, "Kafka broker")
	res := stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"}, "max_messages": 3,
		"sasl": map[string]any{"mechanism": "scram-sha-256", "username": "bob", "password": "pw2"}}))
	if len(res.Messages) != 3 {
		t.Fatalf("%+v", res)
	}
}

func TestKafkaTLS(t *testing.T) {
	srvTLS, caPEM := testTLS(t)
	brokers := startKafka(t, kfake.TLS(srvTLS))
	h := tooltest.New(t, "messaging")
	rec := []any{map[string]any{"value": map[string]any{"text": "over tls"}}}
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec, "tls": true, "timeout_seconds": 5}, "certificate")
	r := h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec, "ca_cert": caPEM})
	if r.Data["tls"].(map[string]any)["version"] == "" {
		t.Fatalf("%s", r.Raw)
	}
	res := stream(t, h.MustOK("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"}, "max_messages": 1, "ca_cert": caPEM}))
	if len(res.Messages) != 1 || res.Messages[0].Data != "over tls" || res.Meta["tls"] == nil {
		t.Fatalf("%+v", res)
	}
}

func TestKafkaGuardBlocksPrivate(t *testing.T) {
	brokers := startKafka(t)
	h := tooltest.New(t, "messaging", tooltest.WithPrivateMode(config.PrivateOptIn))
	rec := []any{map[string]any{"value": map[string]any{"text": "x"}}}
	h.MustFail("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec}, "blocked")
	h.MustFail("kafka_consume", map[string]any{"brokers": brokers, "topics": []string{"events"}}, "blocked")
	h.MustFail("kafka_consume", map[string]any{"brokers": []string{"localhost:9092"}, "topics": []string{"events"}}, "blocked")
	h.MustOK("kafka_produce", map[string]any{"brokers": brokers, "topic": "events", "records": rec, "allow_private": true})
}
