package apitools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/rpcx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type jsonrpcCall struct {
	Method       string `json:"method" jsonschema:"remote method name"`
	Params       any    `json:"params,omitempty" jsonschema:"params: a JSON object (by name) or array (by position)"`
	ID           any    `json:"id,omitempty" jsonschema:"request id (string or integer; default: assigned sequentially)"`
	Notification bool   `json:"notification,omitempty" jsonschema:"send as a notification (no id, no response expected)"`
}

type jsonrpcIn struct {
	URL            string            `json:"url" jsonschema:"JSON-RPC endpoint (http or https)"`
	Method         string            `json:"method,omitempty" jsonschema:"method for a single call (omit when using batch)"`
	Params         any               `json:"params,omitempty" jsonschema:"params for a single call: object or array"`
	ID             any               `json:"id,omitempty" jsonschema:"id for a single call (default 1)"`
	Notification   bool              `json:"notification,omitempty" jsonschema:"send the single call as a notification"`
	Batch          []jsonrpcCall     `json:"batch,omitempty" jsonschema:"several calls sent as one JSON-RPC batch array"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	IncludeHeaders bool              `json:"include_headers,omitempty" jsonschema:"include response headers in the result"`
	Auth           *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

type jsonrpcError struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	Name    string `json:"name,omitempty"`
}

type jsonrpcResult struct {
	ID     any           `json:"id"`
	Method string        `json:"method,omitempty"`
	OK     bool          `json:"ok"`
	Result any           `json:"result"`
	Error  *jsonrpcError `json:"error,omitempty"`
}

type jsonrpcOut struct {
	httpSummary
	Batch      bool            `json:"batch"`
	Responses  []jsonrpcResult `json:"responses"`
	MissingIDs []any           `json:"missing_ids,omitempty"`
	Body       string          `json:"body,omitempty"`
}

func registerJSONRPC(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "jsonrpc_request", "JSON-RPC 2.0 request",
		"Call a JSON-RPC 2.0 endpoint over HTTP POST. Single call: method + params (object or array) + optional id. "+
			"Batch: batch=[{method, params, id?, notification?}] sent as one array. Notifications get no response. "+
			"Responses are matched to requests by id; JSON-RPC errors are results ({ok:false, error:{code, message, data}}), not tool failures. "+
			"missing_ids lists calls the server did not answer.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in jsonrpcIn) (any, error) {
			return jsonrpcRequest(ctx, d, in)
		})
}

func jsonrpcRequest(ctx context.Context, d *tools.Deps, in jsonrpcIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	var calls []rpcx.Call
	batch := len(in.Batch) > 0
	switch {
	case batch && strings.TrimSpace(in.Method) != "":
		return nil, errors.New("set either method (single call) or batch, not both")
	case batch:
		for _, c := range in.Batch {
			calls = append(calls, rpcx.Call{Method: c.Method, Params: c.Params, ID: c.ID, Notification: c.Notification})
		}
	case strings.TrimSpace(in.Method) != "":
		calls = []rpcx.Call{{Method: in.Method, Params: in.Params, ID: in.ID, Notification: in.Notification}}
	default:
		return nil, errors.New("method is required (or pass batch)")
	}
	reqs, err := rpcx.BuildRequests(calls)
	if err != nil {
		return nil, err
	}
	body, err := rpcx.Encode(reqs, batch)
	if err != nil {
		return nil, err
	}
	resp, err := do(ctx, d, in.HTTPOptions, in.Auth, call{Method: "POST", URL: u.String(), Headers: in.Headers,
		Body: bytes.NewReader(body), ContentType: "application/json",
		Defaults: map[string]string{"Accept": "application/json"}})
	if err != nil {
		return nil, err
	}
	out := jsonrpcOut{httpSummary: summarize(resp, in.IncludeHeaders), Batch: batch, Responses: []jsonrpcResult{}}
	if resp.Truncated {
		out.Body = resp.Body
		out.Warnings = append(out.Warnings, "response truncated before it could be parsed: raise max_response_bytes")
		return out, nil
	}

	// Requests that expect an answer, keyed by normalised id.
	pending := map[string]rpcx.Request{}
	var order []string
	for i, r := range reqs {
		if calls[i].Notification {
			continue
		}
		k := rpcx.IDKey(r.ID)
		pending[k] = r
		order = append(order, k)
	}

	parsed, _, perr := rpcx.ParseResponses(rawBody(resp))
	if perr != nil {
		out.Body = truncateString(resp.Body, 8192)
		out.Warnings = append(out.Warnings, perr.Error())
		if resp.Status/100 != 2 {
			out.Warnings = append(out.Warnings, fmt.Sprintf("server answered HTTP %d", resp.Status))
		}
		return out, nil
	}
	for _, p := range parsed {
		r := jsonrpcResult{ID: p.ID, OK: p.Error == nil}
		k := rpcx.IDKey(p.ID)
		if q, ok := pending[k]; ok {
			r.Method = q.Method
			delete(pending, k)
		}
		if p.HasResult {
			r.Result = p.Result
		}
		if p.Error != nil {
			r.Error = &jsonrpcError{Code: p.Error.Code, Message: p.Error.Message, Data: p.Error.Data,
				Name: rpcx.StandardErrorName(p.Error.Code)}
		}
		out.Responses = append(out.Responses, r)
	}
	for _, k := range order {
		if q, ok := pending[k]; ok {
			out.MissingIDs = append(out.MissingIDs, q.ID)
		}
	}
	if resp.Status/100 != 2 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("server answered HTTP %d", resp.Status))
	}
	return out, nil
}
