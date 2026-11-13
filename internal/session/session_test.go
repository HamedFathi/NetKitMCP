package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type fakeHandle struct{ closed bool }

func (f *fakeHandle) Close() error { f.closed = true; return nil }

func TestRegistryLifecycle(t *testing.T) {
	r := New(2, time.Minute)
	a, b := &fakeHandle{}, &fakeHandle{}
	id1, err := r.Add("ws", "wss://x", a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("sio", "https://y", b); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("ws", "z", &fakeHandle{}); err == nil {
		t.Fatal("cap not enforced")
	}
	if got, err := Get[*fakeHandle](r, id1, "ws"); err != nil || got != a {
		t.Fatalf("get: %v", err)
	}
	if _, err := Get[*fakeHandle](r, id1, "sio"); err == nil {
		t.Fatal("kind mismatch not detected")
	}
	if n := len(r.List("ws")); n != 1 {
		t.Fatalf("list ws = %d", n)
	}
	if err := r.Close(id1); err != nil || !a.closed {
		t.Fatal("close failed")
	}
	if _, err := Get[*fakeHandle](r, id1, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestRegistryIdleSweep(t *testing.T) {
	r := New(10, time.Minute)
	now := time.Now()
	r.now = func() time.Time { return now }
	h := &fakeHandle{}
	r.Add("ws", "x", h)
	now = now.Add(2 * time.Minute)
	r.Sweep()
	if !h.closed || len(r.List("")) != 0 {
		t.Fatal("idle handle not swept")
	}
}

func TestBufferTake(t *testing.T) {
	b := NewBuffer(3)
	for i := 0; i < 5; i++ {
		b.Push(types.StreamMessage{Data: "m"})
	}
	res := b.Take(context.Background(), 10, 10*time.Millisecond)
	if len(res.Messages) != 3 || res.Dropped != 2 {
		t.Fatalf("got %d msgs, dropped %d", len(res.Messages), res.Dropped)
	}
	if res.Messages[0].Seq != 3 {
		t.Fatalf("oldest kept seq = %d", res.Messages[0].Seq)
	}
	// Wait times out with no messages.
	start := time.Now()
	res = b.Take(context.Background(), 10, 50*time.Millisecond)
	if len(res.Messages) != 0 || res.EndedBy != types.EndedMaxDuration || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("timeout behaviour: %+v", res)
	}
	// A push wakes a waiting Take.
	go func() { time.Sleep(20 * time.Millisecond); b.Push(types.StreamMessage{Data: "late"}) }()
	res = b.Take(context.Background(), 10, 2*time.Second)
	if len(res.Messages) != 1 || res.Messages[0].Data != "late" {
		t.Fatalf("wake: %+v", res)
	}
	b.CloseWith(&types.CloseInfo{Code: 1000}, nil)
	res = b.Take(context.Background(), 10, time.Second)
	if res.EndedBy != types.EndedPeerClosed || res.Close == nil || res.Close.Code != 1000 {
		t.Fatalf("closed: %+v", res)
	}
}

func TestBufferTakeDrainedLabel(t *testing.T) {
	b := NewBuffer(10)
	b.Push(types.StreamMessage{Data: "a"})
	start := time.Now()
	res := b.Take(context.Background(), 5, 5*time.Second)
	if len(res.Messages) != 1 || res.EndedBy != types.EndedDrained {
		t.Fatalf("got %d messages, ended_by %q; want 1, drained", len(res.Messages), res.EndedBy)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Take waited although messages were buffered")
	}
}
