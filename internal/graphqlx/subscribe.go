package graphqlx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/sse"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Subscription transport names.
const (
	// ProtoTransportWS is the graphql-ws library protocol (subprotocol
	// "graphql-transport-ws").
	ProtoTransportWS = "graphql-transport-ws"
	// ProtoLegacyWS is Apollo's legacy subscriptions-transport-ws protocol
	// (subprotocol "graphql-ws").
	ProtoLegacyWS = "subscriptions-transport-ws"
	// ProtoSSE is graphql-sse in "distinct connections" mode.
	ProtoSSE = "sse"

	// SubprotocolTransportWS and SubprotocolLegacy are the WebSocket
	// subprotocol tokens.
	SubprotocolTransportWS = "graphql-transport-ws"
	SubprotocolLegacy      = "graphql-ws"
)

// Subprotocols returns the WebSocket subprotocols to offer for a protocol
// choice ("auto" offers both, preferring graphql-transport-ws).
func Subprotocols(proto string) []string {
	switch proto {
	case ProtoTransportWS:
		return []string{SubprotocolTransportWS}
	case ProtoLegacyWS:
		return []string{SubprotocolLegacy}
	}
	return []string{SubprotocolTransportWS, SubprotocolLegacy}
}

// ProtocolFor resolves the protocol actually spoken from the requested one
// and the subprotocol the server selected.
func ProtocolFor(requested, negotiated string) string {
	switch requested {
	case ProtoTransportWS, ProtoLegacyWS:
		return requested
	}
	if negotiated == SubprotocolLegacy {
		return ProtoLegacyWS
	}
	return ProtoTransportWS
}

type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WSOptions configure a WebSocket subscription.
type WSOptions struct {
	Protocol         string // ProtoTransportWS or ProtoLegacyWS
	ConnectionParams any
	AckTimeout       time.Duration
}

// RunWS runs one subscription over an established WebSocket connection and
// collects results into coll until it finishes (limits, completion, error
// or peer close). It closes the connection before returning and returns
// protocol metadata.
func RunWS(ctx context.Context, conn *websocket.Conn, op Request, o WSOptions, coll *types.Collector) (*types.StreamResult, map[string]any) {
	if o.AckTimeout <= 0 {
		o.AckTimeout = 10 * time.Second
	}
	legacy := o.Protocol == ProtoLegacyWS
	meta := map[string]any{"protocol": o.Protocol, "subprotocol": conn.Subprotocol()}
	var metaMu sync.Mutex
	setMeta := func(k string, v any) { metaMu.Lock(); meta[k] = v; metaMu.Unlock() }
	incMeta := func(k string) {
		metaMu.Lock()
		n, _ := meta[k].(int)
		meta[k] = n + 1
		metaMu.Unlock()
	}

	readCtx, cancelRead := context.WithCancel(context.Background())
	defer cancelRead()
	incoming := make(chan wsMessage, 64)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := conn.Read(readCtx)
			if err != nil {
				readErr <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var m wsMessage
			if err := json.Unmarshal(data, &m); err != nil {
				coll.Add(types.StreamMessage{Type: "event", Event: "invalid", Data: string(data), Encoding: "text"})
				continue
			}
			select {
			case incoming <- m:
			case <-readCtx.Done():
				return
			}
		}
	}()

	write := func(m any) error {
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, b)
	}

	const opID = "1"
	completedByServer := false
	subscribed := false

	handleClose := func(err error) {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			coll.SetClose(int(ce.Code), ce.Reason)
			if ce.Code == websocket.StatusNormalClosure {
				coll.Finish(types.EndedPeerClosed, nil)
			} else {
				coll.Finish(types.EndedPeerClosed, fmt.Errorf("server closed the connection: %d %s", ce.Code, ce.Reason))
			}
			return
		}
		if errors.Is(err, io.EOF) {
			coll.Finish(types.EndedPeerClosed, nil)
			return
		}
		coll.Finish(types.EndedError, err)
	}

	protoDone := make(chan struct{})
	go func() {
		defer close(protoDone)
		init := map[string]any{"type": "connection_init"}
		if o.ConnectionParams != nil {
			init["payload"] = o.ConnectionParams
		}
		if err := write(init); err != nil {
			coll.Finish(types.EndedError, fmt.Errorf("sending connection_init: %w", err))
			return
		}
		ackTimer := time.NewTimer(o.AckTimeout)
		defer ackTimer.Stop()
	waitAck:
		for {
			select {
			case <-coll.Done():
				return
			case err := <-readErr:
				handleClose(err)
				return
			case <-ackTimer.C:
				coll.Finish(types.EndedError, fmt.Errorf("no connection_ack within %s", o.AckTimeout))
				return
			case m := <-incoming:
				switch m.Type {
				case "connection_ack":
					setMeta("acknowledged", true)
					break waitAck
				case "ping":
					_ = write(pong(m))
					incMeta("pings")
				case "ka":
					incMeta("keepalives")
				case "connection_error":
					coll.Add(types.StreamMessage{Type: "event", Event: "connection_error", Data: string(m.Payload), Encoding: "text"})
					coll.Finish(types.EndedError, fmt.Errorf("connection_error: %s", compact(m.Payload)))
					return
				}
			}
		}
		payload := map[string]any{"query": op.Query}
		if len(op.Variables) > 0 {
			payload["variables"] = op.Variables
		}
		if op.OperationName != "" {
			payload["operationName"] = op.OperationName
		}
		if len(op.Extensions) > 0 {
			payload["extensions"] = op.Extensions
		}
		typ := "subscribe"
		if legacy {
			typ = "start"
		}
		if err := write(map[string]any{"id": opID, "type": typ, "payload": payload}); err != nil {
			coll.Finish(types.EndedError, fmt.Errorf("sending %s: %w", typ, err))
			return
		}
		subscribed = true
		for {
			select {
			case <-coll.Done():
				return
			case err := <-readErr:
				handleClose(err)
				return
			case m := <-incoming:
				switch m.Type {
				case "next", "data":
					coll.Add(types.StreamMessage{Type: "event", Event: "next", ID: m.ID, Data: compact(m.Payload), Encoding: "text"})
				case "error":
					coll.Add(types.StreamMessage{Type: "event", Event: "error", ID: m.ID, Data: compact(m.Payload), Encoding: "text"})
					completedByServer = true
					coll.Finish(types.EndedError, fmt.Errorf("subscription error: %s", truncate(compact(m.Payload), 500)))
					return
				case "complete":
					completedByServer = true
					coll.Add(types.StreamMessage{Type: "event", Event: "complete", ID: m.ID, Data: "", Encoding: "text"})
					coll.Finish(types.EndedComplete, nil)
					return
				case "ping":
					_ = write(pong(m))
					incMeta("pings")
				case "pong":
					incMeta("pongs")
				case "ka":
					incMeta("keepalives")
				case "connection_error":
					coll.Finish(types.EndedError, fmt.Errorf("connection_error: %s", compact(m.Payload)))
					return
				default:
					coll.Add(types.StreamMessage{Type: "event", Event: m.Type, ID: m.ID, Data: compact(m.Payload), Encoding: "text"})
				}
			}
		}
	}()

	res := coll.Wait(ctx)
	<-protoDone
	// Graceful shutdown: stop the operation, then close the socket.
	if subscribed && !completedByServer {
		if legacy {
			_ = write(map[string]any{"id": opID, "type": "stop"})
			_ = write(map[string]any{"type": "connection_terminate"})
		} else {
			_ = write(map[string]any{"id": opID, "type": "complete"})
		}
	}
	closed := make(chan struct{})
	go func() {
		conn.Close(websocket.StatusNormalClosure, "")
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		conn.CloseNow()
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	out := make(map[string]any, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return res, out
}

func pong(ping wsMessage) map[string]any {
	m := map[string]any{"type": "pong"}
	if len(ping.Payload) > 0 {
		m["payload"] = ping.Payload
	}
	return m
}

func compact(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return string(raw)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// RunSSE runs one subscription over graphql-sse "distinct connections"
// mode: a POST with Accept: text/event-stream whose response streams
// `next` events and ends with `complete`. headers are sent as-is (the caller
// sets User-Agent and custom headers). The function returns when the
// collector finishes.
func RunSSE(ctx context.Context, client *http.Client, url string, headers http.Header, op Request, coll *types.Collector) (*types.StreamResult, map[string]any) {
	meta := map[string]any{"protocol": ProtoSSE}
	body, err := json.Marshal(op)
	if err != nil {
		coll.Finish(types.EndedError, err)
		return coll.Result(), meta
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		coll.Finish(types.EndedError, err)
		return coll.Result(), meta
	}
	for k, vs := range headers {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := client.Do(req)
		if err != nil {
			coll.Finish(types.EndedError, err)
			return
		}
		defer resp.Body.Close()
		meta["status"] = resp.StatusCode
		ct := resp.Header.Get("Content-Type")
		meta["content_type"] = ct
		if resp.StatusCode/100 != 2 || !strings.HasPrefix(strings.ToLower(ct), "text/event-stream") {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			coll.Add(types.StreamMessage{Type: "event", Event: "error", Data: string(b), Encoding: "text"})
			coll.Finish(types.EndedError, fmt.Errorf("server answered HTTP %d (%s) instead of an event stream", resp.StatusCode, ct))
			return
		}
		r := sse.NewReader(resp.Body, 0)
		for {
			ev, err := r.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					coll.Finish(types.EndedPeerClosed, nil)
				} else {
					coll.Finish(types.EndedError, err)
				}
				return
			}
			switch ev.Event {
			case "complete":
				coll.Add(types.StreamMessage{Type: "event", Event: "complete", ID: ev.ID, Data: ev.Data, Encoding: "text"})
				coll.Finish(types.EndedComplete, nil)
				return
			default:
				name := ev.Event
				if name == "message" {
					name = "next"
				}
				coll.Add(types.StreamMessage{Type: "event", Event: name, ID: ev.ID, Data: ev.Data, Encoding: "text"})
			}
		}
	}()
	res := coll.Wait(ctx)
	cancel()
	<-done
	return res, meta
}
