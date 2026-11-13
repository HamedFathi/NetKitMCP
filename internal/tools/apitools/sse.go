package apitools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/sse"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type sseIn struct {
	URL         string            `json:"url" jsonschema:"event stream URL (http or https)"`
	Method      string            `json:"method,omitempty" jsonschema:"GET (default) or POST (e.g. LLM streaming APIs)"`
	Body        *types.Payload    `json:"body,omitempty" jsonschema:"request body for POST: text, json, base64 or file"`
	ContentType string            `json:"content_type,omitempty" jsonschema:"request body content type (default: application/json for json bodies)"`
	LastEventID string            `json:"last_event_id,omitempty" jsonschema:"resume a stream: sent as the Last-Event-ID header"`
	StopEvent   string            `json:"stop_event,omitempty" jsonschema:"stop after an event with this event name (it is included)"`
	StopData    string            `json:"stop_data,omitempty" jsonschema:"stop after an event whose data equals this exactly, e.g. [DONE]"`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	Auth        *auth.Config      `json:"auth,omitempty"`
	types.StreamLimits
	types.HTTPOptions
}

func registerSSE(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "sse_listen", "Listen to Server-Sent Events",
		"Open a Server-Sent Events stream (GET, or POST with a body for LLM-style streaming APIs) and collect events. "+
			"Stops after max_messages events, max_duration_seconds, idle_timeout_seconds without events, when the server closes the stream, "+
			"or on stop_event (event name) / stop_data (exact data, e.g. \"[DONE]\"). Each message carries event, id and data; ended_by explains why collection stopped. "+
			"meta.last_event_id can be passed back as last_event_id to resume.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in sseIn) (any, error) {
			return sseListen(ctx, d, in)
		})
}

func sseListen(ctx context.Context, d *tools.Deps, in sseIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
		if !in.Body.IsZero() {
			method = http.MethodPost
		}
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, fmt.Errorf("method must be GET or POST, got %q", in.Method)
	}
	if method == http.MethodGet && !in.Body.IsZero() {
		return nil, errors.New("a body needs method POST")
	}
	payload, err := in.Body.Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, d.Cfg.UploadBytes(0))
	if err != nil {
		return nil, err
	}
	defer payload.Close()

	cl, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	coll := newCollector(d, in.StreamLimits)
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var body io.Reader
	if method == http.MethodPost {
		body = payload.Open()
	}
	req, err := http.NewRequestWithContext(rctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if method == http.MethodPost {
		req.ContentLength = payload.Size
		ct := in.ContentType
		if ct == "" {
			ct = payload.ContentType
		}
		if ct == "" && in.Body != nil && in.Body.JSON != nil {
			ct = "application/json"
		}
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", cl.UserAgent())
	if in.LastEventID != "" {
		req.Header.Set("Last-Event-ID", in.LastEventID)
	}
	applyHeaders(req.Header, in.Headers)

	meta := map[string]any{}
	var reader *sse.Reader
	// lastID is the event ID in effect for the last event returned; the
	// reader may already have parsed further (buffered) events after the
	// collector finished, so reader.LastEventID() can be ahead.
	lastID := in.LastEventID
	// connErr is set when no response arrived at all (refused, blocked by
	// the guard, TLS failure): that is a tool error, not a stream result.
	var connErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := cl.Client.Do(req)
		if err != nil {
			if rctx.Err() == nil {
				connErr = requestError(err, cl)
				coll.Finish(types.EndedError, connErr)
			}
			return
		}
		defer resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		// meta is read only after done is closed.
		meta["status"] = resp.StatusCode
		meta["content_type"] = ct
		meta["protocol"] = resp.Proto
		if resp.StatusCode/100 != 2 || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/event-stream") {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			coll.Add(types.StreamMessage{Type: "event", Event: "error", Data: string(b), Encoding: "text"})
			coll.Finish(types.EndedError, fmt.Errorf("server answered HTTP %d (%s) instead of an event stream", resp.StatusCode, orNone(ct)))
			return
		}
		r := sse.NewReader(resp.Body, int(cl.MaxResponseBytes))
		reader = r
		for {
			ev, err := r.Next()
			if err != nil {
				switch {
				case rctx.Err() != nil:
					// Collection already finished (limit or caller cancel).
				case errors.Is(err, io.EOF):
					coll.Finish(types.EndedPeerClosed, nil)
				case errors.Is(err, sse.ErrLineTooLong):
					coll.Finish(types.EndedError, fmt.Errorf("event line longer than %d bytes: raise max_response_bytes", cl.MaxResponseBytes))
				default:
					coll.Finish(types.EndedError, err)
				}
				return
			}
			m := types.StreamMessage{Type: "event", Event: ev.Event, ID: ev.ID, Data: ev.Data, Encoding: "text"}
			if ev.Retry >= 0 {
				m.Meta = map[string]any{"retry_ms": ev.Retry}
			}
			if !coll.Add(m) {
				return
			}
			lastID = ev.ID
			if (in.StopEvent != "" && ev.Event == in.StopEvent) || (in.StopData != "" && ev.Data == in.StopData) {
				coll.Finish(types.EndedStopEvent, nil)
				return
			}
		}
	}()
	res := coll.Wait(ctx)
	cancel()
	<-done
	if connErr != nil {
		return nil, connErr
	}
	if reader != nil {
		meta["last_event_id"] = lastID
		if n := reader.Comments(); n > 0 {
			meta["comments"] = n
		}
	}
	return finishStream(res, meta, cl), nil
}

func orNone(s string) string {
	if s == "" {
		return "no content type"
	}
	return s
}
