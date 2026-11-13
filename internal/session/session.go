// Package session is the process-local registry of interactive handles
// (WebSocket, Socket.IO and gRPC stream sessions). Handles are application
// state, independent of MCP sessions; they have an idle TTL and a hard cap.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Handle is anything that can be closed.
type Handle interface {
	Close() error
}

// Info describes a registered handle.
type Info struct {
	ID         string `json:"session_id"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
	IdleTTLSec int    `json:"idle_ttl_seconds"`
}

type entry struct {
	kind     string
	target   string
	h        Handle
	created  time.Time
	lastUsed time.Time
}

// Registry holds handles.
type Registry struct {
	mu      sync.Mutex
	items   map[string]*entry
	max     int
	idleTTL time.Duration
	now     func() time.Time
}

// ErrNotFound is returned for unknown or expired handles.
var ErrNotFound = errors.New("session not found (it may have been closed or expired)")

// New creates a registry.
func New(max int, idleTTL time.Duration) *Registry {
	return &Registry{items: map[string]*entry{}, max: max, idleTTL: idleTTL, now: time.Now}
}

// Start runs the idle janitor until ctx ends, then closes everything.
func (r *Registry) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				r.CloseAll()
				return
			case <-t.C:
				r.Sweep()
			}
		}
	}()
}

// Sweep closes idle handles.
func (r *Registry) Sweep() {
	if r.idleTTL <= 0 {
		return
	}
	cutoff := r.now().Add(-r.idleTTL)
	var stale []Handle
	r.mu.Lock()
	for id, e := range r.items {
		if e.lastUsed.Before(cutoff) {
			stale = append(stale, e.h)
			delete(r.items, id)
		}
	}
	r.mu.Unlock()
	for _, h := range stale {
		h.Close()
	}
}

// Add registers a handle and returns its ID. kind is e.g. "ws", "sio",
// "grpc_stream"; target is a redacted description of the remote.
func (r *Registry) Add(kind, target string, h Handle) (string, error) {
	r.Sweep()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && len(r.items) >= r.max {
		return "", fmt.Errorf("session limit reached (%d open); close one first", r.max)
	}
	var b [8]byte
	rand.Read(b[:])
	id := kind + "_" + hex.EncodeToString(b[:])
	now := r.now()
	r.items[id] = &entry{kind: kind, target: target, h: h, created: now, lastUsed: now}
	return id, nil
}

// Get returns the handle with the given ID and kind, refreshing its idle timer.
func Get[T Handle](r *Registry, id, kind string) (T, error) {
	var zero T
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	if !ok {
		return zero, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if kind != "" && e.kind != kind {
		return zero, fmt.Errorf("session %s is a %s session, not %s", id, e.kind, kind)
	}
	h, ok := e.h.(T)
	if !ok {
		return zero, fmt.Errorf("session %s has unexpected type", id)
	}
	e.lastUsed = r.now()
	return h, nil
}

// Remove unregisters a handle without closing it.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.items, id)
	r.mu.Unlock()
}

// Close closes and unregisters a handle.
func (r *Registry) Close(id string) error {
	r.mu.Lock()
	e, ok := r.items[id]
	delete(r.items, id)
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return e.h.Close()
}

// CloseAll closes every handle.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	items := r.items
	r.items = map[string]*entry{}
	r.mu.Unlock()
	for _, e := range items {
		e.h.Close()
	}
}

// List returns handles of the given kind ("" = all).
func (r *Registry) List(kind string) []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Info{}
	for id, e := range r.items {
		if kind != "" && e.kind != kind {
			continue
		}
		out = append(out, Info{
			ID: id, Kind: e.kind, Target: e.target,
			CreatedAt:  e.created.UTC().Format(time.RFC3339),
			LastUsedAt: e.lastUsed.UTC().Format(time.RFC3339),
			IdleTTLSec: int(r.idleTTL.Seconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// Buffer is a bounded ring buffer of stream messages filled by a background
// reader and drained by receive tools.
type Buffer struct {
	mu      sync.Mutex
	msgs    []types.StreamMessage
	cap     int
	seq     int
	dropped int
	closed  bool
	close   *types.CloseInfo
	errText string
	notify  chan struct{}
}

// NewBuffer creates a buffer holding at most capacity messages.
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Buffer{cap: capacity, notify: make(chan struct{})}
}

// Push appends a message, dropping the oldest when full. It assigns Seq/TS.
func (b *Buffer) Push(m types.StreamMessage) {
	b.mu.Lock()
	b.seq++
	m.Seq = b.seq
	if m.TS == "" {
		m.TS = types.Now()
	}
	if m.Dir == "" {
		m.Dir = "in"
	}
	if len(b.msgs) >= b.cap {
		b.msgs = b.msgs[1:]
		b.dropped++
	}
	b.msgs = append(b.msgs, m)
	b.wakeLocked()
	b.mu.Unlock()
}

// NextSeq reserves a sequence number (for outgoing messages recorded elsewhere).
func (b *Buffer) NextSeq() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	return b.seq
}

func (b *Buffer) wakeLocked() {
	close(b.notify)
	b.notify = make(chan struct{})
}

// CloseWith marks the stream closed by the peer or an error.
func (b *Buffer) CloseWith(ci *types.CloseInfo, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	b.close = ci
	if err != nil {
		b.errText = err.Error()
	}
	b.wakeLocked()
}

// Closed reports whether the stream has ended.
func (b *Buffer) Closed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Take waits up to wait for at least one message (or minCount messages)
// then drains up to max messages. It returns a StreamResult whose EndedBy is
// "peer_closed"/"error" when the stream ended and the buffer is empty,
// "max_messages" when max were returned, or "max_duration" when the wait
// elapsed.
func (b *Buffer) Take(ctx context.Context, max int, wait time.Duration) *types.StreamResult {
	if max <= 0 {
		max = 100
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	timedOut := false
	for {
		b.mu.Lock()
		if len(b.msgs) > 0 || b.closed {
			break
		}
		ch := b.notify
		b.mu.Unlock()
		select {
		case <-ch:
		case <-deadline.C:
			timedOut = true
			b.mu.Lock()
			goto drain
		case <-ctx.Done():
			timedOut = true
			b.mu.Lock()
			goto drain
		}
	}
drain:
	defer b.mu.Unlock()
	n := len(b.msgs)
	if n > max {
		n = max
	}
	out := make([]types.StreamMessage, n)
	copy(out, b.msgs[:n])
	b.msgs = b.msgs[n:]
	res := &types.StreamResult{Messages: out, Dropped: b.dropped}
	b.dropped = 0
	switch {
	case n == max:
		res.EndedBy = types.EndedMaxMessages
	case b.closed && len(b.msgs) == 0:
		res.EndedBy = types.EndedPeerClosed
		if b.errText != "" {
			res.EndedBy = types.EndedError
			res.Error = b.errText
		}
		res.Close = b.close
	case timedOut:
		res.EndedBy = types.EndedMaxDuration
	default:
		res.EndedBy = types.EndedDrained
	}
	return res
}

// Pending returns the number of buffered messages.
func (b *Buffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.msgs)
}
