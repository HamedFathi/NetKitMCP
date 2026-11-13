package httptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type requestIn struct {
	Method         string            `json:"method,omitempty" jsonschema:"HTTP method; any token incl. PROPFIND, REPORT, PURGE (default GET, or POST when a body is given)"`
	URL            string            `json:"url" jsonschema:"absolute http:// or https:// URL"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"request headers"`
	Query          map[string]any    `json:"query,omitempty" jsonschema:"query parameters appended to the URL; each value is a string or a list of strings (repeated keys)"`
	Body           *string           `json:"body,omitempty" jsonschema:"raw text body"`
	JSON           any               `json:"json,omitempty" jsonschema:"JSON body (serialized; Content-Type application/json)"`
	BodyBase64     string            `json:"body_base64,omitempty" jsonschema:"binary body as base64 (small payloads only)"`
	BodyFile       string            `json:"body_file,omitempty" jsonschema:"stream the body from this file (inside an allowed read directory)"`
	ContentType    string            `json:"content_type,omitempty" jsonschema:"Content-Type of the body (default derived from the body kind or file extension)"`
	IncludeRequest bool              `json:"include_request,omitempty" jsonschema:"include a redacted echo of the request (method, URL, headers, body size and sha256)"`
	DownloadOptions
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"authentication (type: basic, bearer, api_key, digest, oauth2, aws_sigv4, ...)"`
}

func handleRequest(d *tools.Deps) tools.Handler[requestIn] {
	return func(ctx context.Context, mreq *mcp.CallToolRequest, in requestIn) (any, error) {
		u, err := buildURL(in.URL, in.Query)
		if err != nil {
			return nil, err
		}
		body, err := requestBody(d, in)
		if err != nil {
			return nil, err
		}
		def := "GET"
		if body != nil {
			def = "POST"
		}
		method, err := normalizeMethod(in.Method, def)
		if err != nil {
			return nil, err
		}
		if body != nil && in.ContentType != "" {
			body.contentType = in.ContentType
			body.summary.ContentType = in.ContentType
		}
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

// requestBody resolves the one-of body fields of http_request.
func requestBody(d *tools.Deps, in requestIn) (*bodySource, error) {
	n := 0
	for _, set := range []bool{in.Body != nil, in.JSON != nil, in.BodyBase64 != "", in.BodyFile != ""} {
		if set {
			n++
		}
	}
	if n > 1 {
		return nil, errors.New("set only one of body, json, body_base64, body_file")
	}
	switch {
	case in.Body != nil:
		return bytesSource([]byte(*in.Body), "text", "text/plain; charset=utf-8"), nil
	case in.JSON != nil:
		b, err := json.Marshal(in.JSON)
		if err != nil {
			return nil, fmt.Errorf("json body: %w", err)
		}
		return bytesSource(b, "json", "application/json"), nil
	case in.BodyBase64 != "":
		b, err := types.DecodeBase64(in.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("body_base64: %w", err)
		}
		if max := d.Cfg.MaxInlineBase64Bytes; max > 0 && int64(len(b)) > max {
			return nil, fmt.Errorf("body_base64 is %d bytes, above the %d byte inline limit; put the data in a file and use body_file", len(b), max)
		}
		return bytesSource(b, "base64", "application/octet-stream"), nil
	case in.BodyFile != "":
		fb, err := newFileBody(d.Files, in.BodyFile, d.Cfg.UploadBytes(0))
		if err != nil {
			return nil, err
		}
		return fileSource(fb), nil
	}
	return nil, nil
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
