// Package rpcx implements the JSON-RPC 2.0 and XML-RPC wire formats.
package rpcx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Call is one JSON-RPC call.
type Call struct {
	Method       string
	Params       any // object, array or nil
	ID           any // nil = assign automatically (unless Notification)
	Notification bool
}

// Request is a JSON-RPC 2.0 request object.
type Request struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
	ID      any    `json:"id,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Response is a parsed JSON-RPC response object.
type Response struct {
	ID     any    `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
	// HasResult distinguishes "result": null from a missing result.
	HasResult bool `json:"-"`
}

// BuildRequests validates calls, assigns IDs (sequential integers starting at
// 1, skipping IDs already used) and returns the request objects.
func BuildRequests(calls []Call) ([]Request, error) {
	used := map[string]bool{}
	for _, c := range calls {
		if c.ID != nil && !c.Notification {
			used[IDKey(c.ID)] = true
		}
	}
	next := int64(1)
	out := make([]Request, 0, len(calls))
	for i, c := range calls {
		if strings.TrimSpace(c.Method) == "" {
			return nil, fmt.Errorf("call %d: method is required", i)
		}
		if err := checkParams(c.Params); err != nil {
			return nil, fmt.Errorf("call %d (%s): %w", i, c.Method, err)
		}
		r := Request{JSONRPC: "2.0", Method: c.Method, Params: c.Params}
		if !c.Notification {
			id := c.ID
			if id == nil {
				for used[IDKey(next)] {
					next++
				}
				id = next
				used[IDKey(next)] = true
				next++
			} else if err := checkID(id); err != nil {
				return nil, fmt.Errorf("call %d (%s): %w", i, c.Method, err)
			}
			r.ID = id
		}
		out = append(out, r)
	}
	return out, nil
}

func checkParams(p any) error {
	if p == nil {
		return nil
	}
	switch reflect.ValueOf(p).Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.Struct:
		return nil
	}
	return errors.New("params must be an object or an array (JSON-RPC 2.0 §4.2)")
}

func checkID(id any) error {
	switch v := id.(type) {
	case string, json.Number, int, int64:
		return nil
	case float64:
		if v != float64(int64(v)) {
			return errors.New("id should be a string or an integer")
		}
		return nil
	}
	return fmt.Errorf("id must be a string or a number, got %T", id)
}

// IDKey normalises an id for matching (numbers compare by value).
func IDKey(id any) string {
	switch v := id.(type) {
	case nil:
		return "null"
	case string:
		b, _ := json.Marshal(v)
		return string(b)
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprint(int64(v))
		}
		return fmt.Sprint(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return fmt.Sprint(i)
		}
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

// Encode serialises requests: a single object, or an array when batch.
func Encode(reqs []Request, batch bool) ([]byte, error) {
	if batch {
		return json.Marshal(reqs)
	}
	if len(reqs) != 1 {
		return nil, fmt.Errorf("non-batch request needs exactly one call")
	}
	return json.Marshal(reqs[0])
}

// ParseResponses parses a single response object or a batch array. An empty
// body (all notifications) yields no responses.
func ParseResponses(body []byte) ([]Response, bool, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, false, nil
	}
	dec := func(b []byte, v any) error {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		return d.Decode(v)
	}
	if body[0] == '[' {
		var raws []json.RawMessage
		if err := dec(body, &raws); err != nil {
			return nil, true, fmt.Errorf("invalid JSON-RPC batch response: %w", err)
		}
		out := make([]Response, 0, len(raws))
		for _, raw := range raws {
			r, err := parseOne(raw, dec)
			if err != nil {
				return nil, true, err
			}
			out = append(out, r)
		}
		return out, true, nil
	}
	r, err := parseOne(body, dec)
	if err != nil {
		return nil, false, err
	}
	return []Response{r}, false, nil
}

func parseOne(raw []byte, dec func([]byte, any) error) (Response, error) {
	var m map[string]json.RawMessage
	if err := dec(raw, &m); err != nil {
		return Response{}, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	var r Response
	if v, ok := m["id"]; ok {
		if err := dec(v, &r.ID); err != nil {
			return Response{}, err
		}
	}
	if v, ok := m["result"]; ok {
		r.HasResult = true
		if err := dec(v, &r.Result); err != nil {
			return Response{}, err
		}
	}
	if v, ok := m["error"]; ok && string(bytes.TrimSpace(v)) != "null" {
		var e Error
		if err := dec(v, &e); err != nil {
			// Non-conforming error object: keep it verbatim in data.
			var anyErr any
			_ = dec(v, &anyErr)
			e = Error{Code: 0, Message: "non-standard error object", Data: anyErr}
		}
		r.Error = &e
	}
	if !r.HasResult && r.Error == nil {
		return Response{}, fmt.Errorf("invalid JSON-RPC response: neither result nor error present: %s", truncate(string(raw), 200))
	}
	return r, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// StandardErrorName names the reserved JSON-RPC error codes.
func StandardErrorName(code int64) string {
	switch {
	case code == -32700:
		return "parse error"
	case code == -32600:
		return "invalid request"
	case code == -32601:
		return "method not found"
	case code == -32602:
		return "invalid params"
	case code == -32603:
		return "internal error"
	case code <= -32000 && code >= -32099:
		return "server error"
	}
	return ""
}
