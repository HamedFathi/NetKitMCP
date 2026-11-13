// Package progress sends MCP progress notifications for long transfers when
// the client supplied a progress token.
package progress

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Reporter sends throttled progress notifications. A nil or token-less
// Reporter is a no-op, so callers never need to check.
type Reporter struct {
	mu    sync.Mutex
	ss    *mcp.ServerSession
	token any
	last  time.Time
	every time.Duration
}

// FromRequest returns a reporter for the tool call (never nil).
func FromRequest(req *mcp.CallToolRequest) *Reporter {
	r := &Reporter{every: 250 * time.Millisecond}
	if req != nil && req.Params != nil && req.Session != nil {
		r.token = req.Params.GetProgressToken()
		r.ss = req.Session
	}
	return r
}

// Enabled reports whether notifications will be sent.
func (r *Reporter) Enabled() bool { return r != nil && r.token != nil && r.ss != nil }

// Report sends progress (throttled unless done == total).
func (r *Reporter) Report(ctx context.Context, done, total int64, msg string) {
	if !r.Enabled() {
		return
	}
	r.mu.Lock()
	now := time.Now()
	if now.Sub(r.last) < r.every && (total <= 0 || done < total) {
		r.mu.Unlock()
		return
	}
	r.last = now
	r.mu.Unlock()
	p := &mcp.ProgressNotificationParams{ProgressToken: r.token, Progress: float64(done), Message: msg}
	if total > 0 {
		p.Total = float64(total)
	}
	_ = r.ss.NotifyProgress(ctx, p)
}

// Func returns a callback suitable for transfer loops.
func (r *Reporter) Func(ctx context.Context, msg string) func(done, total int64) {
	return func(done, total int64) { r.Report(ctx, done, total, msg) }
}

// Reader wraps rd so reads report progress against total.
func (r *Reporter) Reader(ctx context.Context, rd io.Reader, total int64, msg string) io.Reader {
	if !r.Enabled() {
		return rd
	}
	return &reader{r: rd, fn: r.Func(ctx, msg), total: total}
}

type reader struct {
	r     io.Reader
	n     int64
	total int64
	fn    func(done, total int64)
}

func (p *reader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if n > 0 {
		p.fn(p.n, p.total)
	}
	return n, err
}
