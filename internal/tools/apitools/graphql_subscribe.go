package apitools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/graphqlx"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type subscribeIn struct {
	URL               string            `json:"url" jsonschema:"subscription endpoint: ws:// or wss:// (http(s) also accepted) for WebSocket protocols, http(s) for sse"`
	Query             string            `json:"query" jsonschema:"GraphQL subscription document"`
	Variables         map[string]any    `json:"variables,omitempty" jsonschema:"operation variables"`
	OperationName     string            `json:"operation_name,omitempty" jsonschema:"operation to run when the document has several"`
	Extensions        map[string]any    `json:"extensions,omitempty" jsonschema:"request extensions object"`
	Protocol          string            `json:"protocol,omitempty" jsonschema:"auto (default: graphql-transport-ws, or the legacy protocol if the server picks it), graphql-transport-ws, subscriptions-transport-ws or sse"`
	ConnectionParams  any               `json:"connection_params,omitempty" jsonschema:"payload of connection_init (e.g. {authToken: ...}) for WebSocket protocols"`
	AckTimeoutSeconds float64           `json:"ack_timeout_seconds,omitempty" jsonschema:"how long to wait for connection_ack (default 10)"`
	Headers           map[string]string `json:"headers,omitempty" jsonschema:"extra handshake / request headers"`
	Auth              *auth.Config      `json:"auth,omitempty"`
	types.StreamLimits
	types.HTTPOptions
}

func registerGraphQLSubscribe(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "graphql_subscribe", "GraphQL subscription",
		"Run a bounded GraphQL subscription and collect the events. Protocols: graphql-transport-ws (graphql-ws library, default), legacy subscriptions-transport-ws (Apollo), or sse (graphql-sse distinct-connections mode). "+
			"connection_params is sent in connection_init. Stops after max_messages events, max_duration_seconds, idle_timeout_seconds without events, or when the server completes. "+
			"Each message has event next|error|complete and data = the JSON payload; ended_by explains why collection stopped.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in subscribeIn) (any, error) {
			return graphqlSubscribe(ctx, d, in)
		})
}

func graphqlSubscribe(ctx context.Context, d *tools.Deps, in subscribeIn) (any, error) {
	if strings.TrimSpace(in.Query) == "" {
		return nil, errors.New("query is required")
	}
	proto := strings.ToLower(strings.TrimSpace(in.Protocol))
	switch proto {
	case "", "auto":
		proto = "auto"
	case "graphql-transport-ws", "graphql-ws-transport", "transport-ws":
		proto = graphqlx.ProtoTransportWS
	case "subscriptions-transport-ws", "legacy", "apollo":
		proto = graphqlx.ProtoLegacyWS
	case "graphql-ws":
		return nil, errors.New(`"graphql-ws" is ambiguous: use graphql-transport-ws (graphql-ws library) or subscriptions-transport-ws (legacy Apollo, subprotocol graphql-ws)`)
	case "sse", "graphql-sse":
		proto = graphqlx.ProtoSSE
	default:
		return nil, fmt.Errorf("unknown protocol %q (use auto, graphql-transport-ws, subscriptions-transport-ws or sse)", in.Protocol)
	}
	u, err := checkURL(in.URL, "ws", "wss", "http", "https")
	if err != nil {
		return nil, err
	}
	op := graphqlx.Request{Query: in.Query, Variables: in.Variables, OperationName: in.OperationName, Extensions: in.Extensions}
	coll := newCollector(d, in.StreamLimits)

	if proto == graphqlx.ProtoSSE {
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		}
		cl, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
		if err != nil {
			return nil, err
		}
		defer cl.Close()
		h := http.Header{}
		h.Set("User-Agent", cl.UserAgent())
		applyHeaders(h, in.Headers)
		res, meta := graphqlx.RunSSE(ctx, cl.Client, u.String(), h, op, coll)
		if _, answered := meta["status"]; !answered && res.EndedBy == types.EndedError && len(res.Messages) == 0 && ctx.Err() == nil {
			// No response at all (refused, blocked by the guard, TLS
			// failure): a tool error, like a failed WebSocket handshake.
			return nil, requestError(errors.New(res.Error), cl)
		}
		return finishStream(res, meta, cl), nil
	}

	opts := in.HTTPOptions
	opts.HTTPVersion = "1.1"
	cl, err := d.NewHTTPClient(opts, in.Auth)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	h := http.Header{}
	h.Set("User-Agent", cl.UserAgent())
	applyHeaders(h, in.Headers)
	dialCtx, cancel := cl.Context(ctx)
	defer cancel()
	conn, resp, err := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{
		HTTPClient:   cl.Client,
		HTTPHeader:   h,
		Subprotocols: graphqlx.Subprotocols(proto),
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("WebSocket handshake failed with HTTP %d: %w", resp.StatusCode, err)
		}
		return nil, requestError(err, cl)
	}
	conn.SetReadLimit(cl.MaxResponseBytes)
	ack := 10 * time.Second
	if in.AckTimeoutSeconds > 0 {
		ack = time.Duration(in.AckTimeoutSeconds * float64(time.Second))
	}
	spoken := graphqlx.ProtocolFor(proto, conn.Subprotocol())
	res, meta := graphqlx.RunWS(ctx, conn, op, graphqlx.WSOptions{
		Protocol: spoken, ConnectionParams: in.ConnectionParams, AckTimeout: ack,
	}, coll)
	if resp != nil {
		meta["handshake_status"] = resp.StatusCode
	}
	return finishStream(res, meta, cl), nil
}

func finishStream(res *types.StreamResult, meta map[string]any, cl *httpx.Client) *types.StreamResult {
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	for k, v := range meta {
		res.Meta[k] = v
	}
	if cl != nil && cl.Insecure {
		res.Meta["warnings"] = []string{"TLS certificate verification was disabled (insecure_skip_verify)"}
	}
	return res
}
