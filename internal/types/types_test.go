package types

import (
	"context"
	"testing"
	"time"
)

func TestCollectorMaxMessages(t *testing.T) {
	c := NewCollector(2, time.Second, 0, 0)
	c.Add(StreamMessage{Dir: "out", Data: "hi"})
	c.Add(StreamMessage{Data: "a"})
	c.Add(StreamMessage{Data: "b"})
	if c.Add(StreamMessage{Data: "c"}) {
		t.Fatal("add after finish should report false")
	}
	r := c.Wait(context.Background())
	if r.EndedBy != EndedMaxMessages || len(r.Messages) != 3 || r.Messages[2].Seq != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestCollectorIdleAndDuration(t *testing.T) {
	c := NewCollector(100, 2*time.Second, 50*time.Millisecond, 0)
	start := time.Now()
	r := c.Wait(context.Background())
	if r.EndedBy != EndedIdle || time.Since(start) > time.Second {
		t.Fatalf("idle: %+v", r)
	}
	c = NewCollector(100, 60*time.Millisecond, 0, 0)
	r = c.Wait(context.Background())
	if r.EndedBy != EndedMaxDuration || r.Messages == nil {
		t.Fatalf("duration: %+v", r)
	}
}

func TestCollectorByteCap(t *testing.T) {
	c := NewCollector(10, time.Second, 0, 4)
	c.Add(StreamMessage{Data: "abc"})
	c.Add(StreamMessage{Data: "defgh"})
	c.Finish(EndedComplete, nil)
	r := c.Result()
	if !r.Truncated || r.Messages[1].Data != "" || r.Messages[1].Meta["omitted_bytes"] != int64(5) {
		t.Fatalf("%+v", r)
	}
}

func TestEncodeBody(t *testing.T) {
	if _, enc := EncodeBody([]byte("hello\n"), "text/plain"); enc != "text" {
		t.Fatal("text")
	}
	if _, enc := EncodeBody([]byte{0xff, 0x00, 0x01}, ""); enc != "base64" {
		t.Fatal("binary")
	}
	if _, enc := EncodeBody([]byte("ok"), "image/png"); enc != "base64" {
		t.Fatal("image")
	}
}

func TestPayloadValidate(t *testing.T) {
	s := "x"
	p := &Payload{Text: &s, Base64: "eA=="}
	if p.Validate() == nil {
		t.Fatal("two fields should be rejected")
	}
	r, err := (&Payload{JSON: map[string]any{"a": 1}}).Resolve(nil, 0, 0)
	if err != nil || string(r.Data) != `{"a":1}` {
		t.Fatalf("%v %s", err, r.Data)
	}
	r, err = (&Payload{Base64: "aGk"}).Resolve(nil, 0, 0)
	if err != nil || string(r.Data) != "hi" {
		t.Fatalf("raw base64: %v", err)
	}
	if _, err := (&Payload{Base64: "aGVsbG8="}).Resolve(nil, 2, 0); err == nil {
		t.Fatal("base64 limit ignored")
	}
}
