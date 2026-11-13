package types

import (
	"context"
	"sync"
	"time"
)

// Collector gathers messages for a bounded one-shot stream. Producers call
// Add; the consumer calls Wait, which returns when a limit is hit, the
// context ends, or Finish is called.
type Collector struct {
	mu          sync.Mutex
	msgs        []StreamMessage
	seq         int
	inCount     int
	maxMessages int
	maxBytes    int64
	bytes       int64
	truncated   bool
	endedBy     string
	errText     string
	closeInfo   *CloseInfo
	done        chan struct{}
	activity    chan struct{}
	maxDuration time.Duration
	idle        time.Duration
}

// NewCollector creates a collector. maxMessages counts only incoming
// messages. maxBytes bounds total data retained (0 = 8 MiB).
func NewCollector(maxMessages int, maxDuration, idle time.Duration, maxBytes int64) *Collector {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	return &Collector{
		maxMessages: maxMessages,
		maxDuration: maxDuration,
		idle:        idle,
		maxBytes:    maxBytes,
		done:        make(chan struct{}),
		activity:    make(chan struct{}, 1),
	}
}

// Done is closed when the collector has finished.
func (c *Collector) Done() <-chan struct{} { return c.done }

// Add records a message. dir is "in" or "out". It assigns Seq and TS if
// unset. It returns false once the collector is finished.
func (c *Collector) Add(m StreamMessage) bool {
	c.mu.Lock()
	if c.endedBy != "" {
		c.mu.Unlock()
		return false
	}
	c.seq++
	m.Seq = c.seq
	if m.TS == "" {
		m.TS = Now()
	}
	if m.Dir == "" {
		m.Dir = "in"
	}
	size := int64(len(m.Data))
	if c.bytes+size > c.maxBytes {
		c.truncated = true
		m.Data = ""
		m.Meta = mergeMeta(m.Meta, map[string]any{"omitted_bytes": size})
	} else {
		c.bytes += size
	}
	c.msgs = append(c.msgs, m)
	if m.Dir == "in" {
		c.inCount++
	}
	reached := m.Dir == "in" && c.maxMessages > 0 && c.inCount >= c.maxMessages
	c.mu.Unlock()
	select {
	case c.activity <- struct{}{}:
	default:
	}
	if reached {
		c.Finish(EndedMaxMessages, nil)
	}
	return true
}

func mergeMeta(a, b map[string]any) map[string]any {
	if a == nil {
		a = map[string]any{}
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}

// Finish ends collection with a reason (first call wins).
func (c *Collector) Finish(endedBy string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.endedBy != "" {
		return
	}
	c.endedBy = endedBy
	if err != nil {
		c.errText = err.Error()
	}
	close(c.done)
}

// SetClose records close details.
func (c *Collector) SetClose(code int, reason string) {
	c.mu.Lock()
	c.closeInfo = &CloseInfo{Code: code, Reason: reason}
	c.mu.Unlock()
}

// Wait blocks until a limit fires and returns the result.
func (c *Collector) Wait(ctx context.Context) *StreamResult {
	var durC <-chan time.Time
	if c.maxDuration > 0 {
		t := time.NewTimer(c.maxDuration)
		defer t.Stop()
		durC = t.C
	}
	var idleT *time.Timer
	var idleC <-chan time.Time
	if c.idle > 0 {
		idleT = time.NewTimer(c.idle)
		defer idleT.Stop()
		idleC = idleT.C
	}
loop:
	for {
		select {
		case <-c.done:
			break loop
		case <-ctx.Done():
			c.Finish(EndedMaxDuration, nil)
		case <-durC:
			c.Finish(EndedMaxDuration, nil)
		case <-idleC:
			c.Finish(EndedIdle, nil)
		case <-c.activity:
			if idleT != nil {
				if !idleT.Stop() {
					select {
					case <-idleT.C:
					default:
					}
				}
				idleT.Reset(c.idle)
			}
		}
	}
	return c.Result()
}

// Result snapshots the collected result.
func (c *Collector) Result() *StreamResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	msgs := c.msgs
	if msgs == nil {
		msgs = []StreamMessage{}
	}
	return &StreamResult{
		Messages:  msgs,
		EndedBy:   c.endedBy,
		Close:     c.closeInfo,
		Error:     c.errText,
		Truncated: c.truncated,
	}
}

// Limits resolves StreamLimits into concrete values using defaults.
func (l StreamLimits) Resolve(defMessages, maxMessages int, defDur, maxDur time.Duration) (int, time.Duration, time.Duration) {
	n := l.MaxMessages
	if n <= 0 {
		n = defMessages
	}
	if n > maxMessages {
		n = maxMessages
	}
	d := defDur
	if l.MaxDurationSeconds > 0 {
		d = time.Duration(l.MaxDurationSeconds * float64(time.Second))
	}
	if d > maxDur {
		d = maxDur
	}
	var idle time.Duration
	if l.IdleTimeoutSeconds > 0 {
		idle = time.Duration(l.IdleTimeoutSeconds * float64(time.Second))
	}
	return n, d, idle
}
