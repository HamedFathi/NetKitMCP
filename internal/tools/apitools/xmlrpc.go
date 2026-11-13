package apitools

import (
	"bytes"
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/rpcx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type xmlrpcIn struct {
	URL            string            `json:"url" jsonschema:"XML-RPC endpoint (http or https)"`
	Method         string            `json:"method" jsonschema:"methodName to call"`
	Params         []any             `json:"params,omitempty" jsonschema:"positional params as JSON; force a type with {\"$type\": \"int|i4|i8|double|boolean|string|base64|dateTime.iso8601|nil\", \"value\": ...}"`
	AllowNil       bool              `json:"allow_nil,omitempty" jsonschema:"encode JSON null as the <nil/> extension (otherwise null is rejected)"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	IncludeHeaders bool              `json:"include_headers,omitempty" jsonschema:"include response headers in the result"`
	Auth           *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

type xmlrpcOut struct {
	httpSummary
	OK     bool        `json:"ok"`
	Result any         `json:"result"`
	Params []any       `json:"params,omitempty"`
	Fault  *rpcx.Fault `json:"fault,omitempty"`
	Body   string      `json:"body,omitempty"`
}

func registerXMLRPC(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "xmlrpc_request", "XML-RPC request",
		"Call an XML-RPC method over HTTP POST. params are positional JSON values: numbers become int or double, strings, booleans, arrays and objects (struct) map naturally; "+
			"force a type with {\"$type\": \"base64\", \"value\": \"...\"} (also i8, dateTime.iso8601, nil). "+
			"Returns result (the first return value). A fault is a result ({ok:false, fault:{faultCode, faultString}}), not a tool failure.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in xmlrpcIn) (any, error) {
			return xmlrpcRequest(ctx, d, in)
		})
}

func xmlrpcRequest(ctx context.Context, d *tools.Deps, in xmlrpcIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	body, err := rpcx.EncodeCall(in.Method, in.Params, rpcx.XMLRPCOptions{AllowNil: in.AllowNil})
	if err != nil {
		return nil, err
	}
	resp, err := do(ctx, d, in.HTTPOptions, in.Auth, call{Method: "POST", URL: u.String(), Headers: in.Headers,
		Body: bytes.NewReader(body), ContentType: "text/xml; charset=utf-8",
		Defaults: map[string]string{"Accept": "text/xml, application/xml;q=0.9"}})
	if err != nil {
		return nil, err
	}
	out := xmlrpcOut{httpSummary: summarize(resp, in.IncludeHeaders)}
	if resp.Truncated {
		out.Body = resp.Body
		out.Warnings = append(out.Warnings, "response truncated before it could be parsed: raise max_response_bytes")
		return out, nil
	}
	dec, derr := rpcx.DecodeResponse(bytes.NewReader(rawBody(resp)))
	if derr != nil {
		out.Body = truncateString(resp.Body, 8192)
		out.Warnings = append(out.Warnings, "response is not a valid XML-RPC methodResponse: "+derr.Error())
		if resp.Status/100 != 2 {
			out.Warnings = append(out.Warnings, fmt.Sprintf("server answered HTTP %d", resp.Status))
		}
		return out, nil
	}
	out.Fault = dec.Fault
	out.OK = dec.Fault == nil
	if len(dec.Params) > 0 {
		out.Result = dec.Params[0]
	}
	if len(dec.Params) > 1 {
		out.Params = dec.Params
	}
	if resp.Status/100 != 2 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("server answered HTTP %d", resp.Status))
	}
	return out, nil
}
