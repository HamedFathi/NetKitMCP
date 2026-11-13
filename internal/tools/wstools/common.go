package wstools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupWS, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerWS(s, d)
	registerWSSession(s, d)
	registerSIO(s, d)
	registerSIOSession(s, d)
}

// Session kinds.
const (
	kindWS  = "ws"
	kindSIO = "sio"
)

// connOptions are the handshake options shared by WebSocket and Socket.IO tools.
type connOptions struct {
	Headers         map[string]string `json:"headers,omitempty" jsonschema:"extra handshake request headers"`
	Origin          string            `json:"origin,omitempty" jsonschema:"Origin header to send (none by default)"`
	Compression     bool              `json:"compression,omitempty" jsonschema:"negotiate permessage-deflate compression"`
	MaxMessageBytes int64             `json:"max_message_bytes,omitempty" jsonschema:"maximum size of one incoming message (default 1 MiB)"`
	Proxy           string            `json:"proxy,omitempty" jsonschema:"proxy URL (http, https or socks5)"`
	Auth            *auth.Config      `json:"auth,omitempty"`
	types.NetOptions
}

// newClient builds the guarded HTTP/1.1 client used for the handshake (and
// Socket.IO polling). minTimeout raises the transport's response-header
// timeout for long-polling.
func newClient(d *tools.Deps, o connOptions, minTimeout time.Duration) (*httpx.Client, error) {
	opts := types.HTTPOptions{NetOptions: o.NetOptions, Proxy: o.Proxy, HTTPVersion: "1.1"}
	if minTimeout > 0 && d.Cfg.Timeout(opts.TimeoutSeconds) < minTimeout {
		opts.TimeoutSeconds = minTimeout.Seconds()
	}
	return d.NewHTTPClient(opts, o.Auth)
}

func (o connOptions) warnings() []string {
	if o.InsecureSkipVerify {
		return []string{"insecure_skip_verify is set: the server certificate was not verified"}
	}
	return nil
}

func secs(v float64) time.Duration { return time.Duration(v * float64(time.Second)) }

// matcher builds a stop condition from a substring or regular expression.
func matcher(pattern string, isRegex bool) (func(string) bool, error) {
	if pattern == "" {
		return nil, nil
	}
	if isRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("stop_on: %w", err)
		}
		return re.MatchString, nil
	}
	return func(s string) bool { return strings.Contains(s, pattern) }, nil
}

// sleepCtx waits for d or until ctx/done ends; it reports whether the wait completed.
func sleepCtx(ctx context.Context, done <-chan struct{}, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-done:
		return false
	}
}

// receiveIn is the input of ws_receive / sio_receive.
type receiveIn struct {
	SessionID   string  `json:"session_id" jsonschema:"session handle"`
	MaxMessages int     `json:"max_messages,omitempty" jsonschema:"return at most this many buffered messages (default 100)"`
	WaitSeconds float64 `json:"wait_seconds,omitempty" jsonschema:"wait up to this many seconds for a message when the buffer is empty (default 1)"`
}

func (in receiveIn) wait(d *tools.Deps) time.Duration {
	if in.WaitSeconds <= 0 {
		return time.Second
	}
	w := secs(in.WaitSeconds)
	if w > d.Cfg.MaxStreamTime {
		w = d.Cfg.MaxStreamTime
	}
	return w
}

// stater is implemented by live session handles for ws_list.
type stater interface {
	state() map[string]any
}

// live maps session IDs to their handles so ws_list can report state
// without refreshing idle timers.
var live sync.Map

// drain returns what is left in a buffer without waiting.
func drain(ctx context.Context, b *session.Buffer, max int) *types.StreamResult {
	return b.Take(ctx, max, 0)
}
