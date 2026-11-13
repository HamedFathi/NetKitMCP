package httptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type formIn struct {
	Method         string            `json:"method,omitempty" jsonschema:"HTTP method (default POST)"`
	URL            string            `json:"url" jsonschema:"absolute http:// or https:// URL"`
	Fields         any               `json:"fields" jsonschema:"form fields: a list of {name, value} objects (order kept, names may repeat) or an object mapping name to a string or list of strings"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"request headers"`
	Query          map[string]any    `json:"query,omitempty" jsonschema:"query parameters appended to the URL; each value is a string or a list of strings"`
	IncludeRequest bool              `json:"include_request,omitempty" jsonschema:"include a redacted echo of the request"`
	DownloadOptions
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"authentication"`
}

func handleForm(d *tools.Deps) tools.Handler[formIn] {
	return func(ctx context.Context, mreq *mcp.CallToolRequest, in formIn) (any, error) {
		u, err := buildURL(in.URL, in.Query)
		if err != nil {
			return nil, err
		}
		fields, err := parseFields(in.Fields)
		if err != nil {
			return nil, err
		}
		method, err := normalizeMethod(in.Method, "POST")
		if err != nil {
			return nil, err
		}
		body := bytesSource([]byte(encodeOrdered(fields)), "form", "application/x-www-form-urlencoded")
		return send(ctx, mreq, d, sendSpec{
			method:         method,
			url:            u,
			headers:        in.Headers,
			body:           body,
			download:       in.DownloadOptions,
			includeRequest: in.IncludeRequest,
			opts:           in.HTTPOptions,
			auth:           in.Auth,
		})
	}
}

// parseFields accepts a list of {name, value} objects or a map of
// name -> string | list.
func parseFields(v any) ([]nameValue, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return toValues(x, "field")
	case []any:
		out := make([]nameValue, 0, len(x))
		for i, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("fields[%d]: expected an object with name and value", i)
			}
			name, _ := m["name"].(string)
			if name == "" {
				return nil, fmt.Errorf("fields[%d]: name is required", i)
			}
			vals, err := scalarList(m["value"])
			if err != nil {
				return nil, fmt.Errorf("fields[%d] %q: %w", i, name, err)
			}
			for _, s := range vals {
				out = append(out, nameValue{name, s})
			}
		}
		return out, nil
	default:
		return nil, errors.New("fields must be a list of {name, value} objects or an object of name -> value")
	}
}
