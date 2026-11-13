package apitools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/graphqlx"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type graphqlFile struct {
	VariablePath  string   `json:"variable_path,omitempty" jsonschema:"where the file goes in the operation, e.g. variables.file or variables.files.0"`
	VariablePaths []string `json:"variable_paths,omitempty" jsonschema:"several paths that share this file"`
	File          string   `json:"file" jsonschema:"path of the file inside an allowed read directory"`
	Filename      string   `json:"filename,omitempty" jsonschema:"filename sent to the server (default: base name of file)"`
	ContentType   string   `json:"content_type,omitempty" jsonschema:"part content type (default: detected from the extension)"`
}

type graphqlIn struct {
	URL                string            `json:"url" jsonschema:"GraphQL endpoint (http or https)"`
	Query              string            `json:"query,omitempty" jsonschema:"GraphQL document (may be omitted when persisted_query_hash is set)"`
	Variables          map[string]any    `json:"variables,omitempty" jsonschema:"operation variables"`
	OperationName      string            `json:"operation_name,omitempty" jsonschema:"operation to run when the document has several"`
	Extensions         map[string]any    `json:"extensions,omitempty" jsonschema:"request extensions object"`
	PersistedQueryHash string            `json:"persisted_query_hash,omitempty" jsonschema:"sha256 hash for Apollo automatic persisted queries (adds extensions.persistedQuery)"`
	Method             string            `json:"method,omitempty" jsonschema:"POST (default) or GET (query string encoding, for persisted/cached queries)"`
	Files              []graphqlFile     `json:"files,omitempty" jsonschema:"file uploads (GraphQL multipart request spec); streamed from disk, POST only"`
	Headers            map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	IncludeHeaders     bool              `json:"include_headers,omitempty" jsonschema:"include response headers in the result"`
	Auth               *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

type graphqlOut struct {
	httpSummary
	Data       json.RawMessage  `json:"data"`
	Errors     json.RawMessage  `json:"errors,omitempty"`
	Extensions json.RawMessage  `json:"extensions,omitempty"`
	Body       string           `json:"body,omitempty"`
	Uploaded   []types.FileInfo `json:"uploaded_files,omitempty"`
}

type introspectIn struct {
	URL                 string            `json:"url" jsonschema:"GraphQL endpoint (http or https)"`
	Format              string            `json:"format,omitempty" jsonschema:"sdl (default) or json (raw introspection result)"`
	TypeName            string            `json:"type_name,omitempty" jsonschema:"print only this type (or @directive)"`
	IncludeDescriptions bool              `json:"include_descriptions,omitempty" jsonschema:"include descriptions in the SDL (default false, more compact)"`
	Headers             map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	Auth                *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

type introspectOut struct {
	Status     int               `json:"status"`
	StatusText string            `json:"status_text"`
	SDL        string            `json:"sdl,omitempty"`
	Schema     json.RawMessage   `json:"schema,omitempty"`
	Counts     map[string]int    `json:"type_counts,omitempty"`
	RootTypes  map[string]string `json:"root_types,omitempty"`
	Errors     json.RawMessage   `json:"errors,omitempty"`
	Body       string            `json:"body,omitempty"`
	TimingMS   types.Timing      `json:"timing_ms"`
	Warnings   []string          `json:"warnings,omitempty"`
}

func registerGraphQL(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "graphql_request", "GraphQL request",
		"Run a GraphQL query or mutation over HTTP. Returns the HTTP status plus data, errors and extensions separately (GraphQL errors are results, not tool failures). "+
			"Uploads files with the GraphQL multipart request spec: files=[{variable_path: \"variables.file\", file: \"/path\"}] (streamed from disk, never buffered). "+
			"method=GET sends the operation in the query string (persisted or cached queries; persisted_query_hash adds the APQ extension). "+
			"Use graphql_introspect first to learn the schema.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in graphqlIn) (any, error) {
			return graphqlRequest(ctx, d, in)
		})
	tools.Add(s, d, "graphql_introspect", "GraphQL introspection",
		"Fetch a GraphQL schema with the standard introspection query and return it as compact SDL (types, fields with arguments and defaults, enums, inputs, interfaces, unions, scalars, custom directives). "+
			"type_name prints a single type; include_descriptions adds docs; format=json returns the raw introspection result. Fails gracefully (errors in the result) when introspection is disabled.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in introspectIn) (any, error) {
			return graphqlIntrospect(ctx, d, in)
		})
}

func graphqlRequest(ctx context.Context, d *tools.Deps, in graphqlIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	op := graphqlx.Request{Query: in.Query, Variables: in.Variables, OperationName: in.OperationName, Extensions: in.Extensions}
	op.PersistedQuery(in.PersistedQueryHash)
	if strings.TrimSpace(op.Query) == "" && in.PersistedQueryHash == "" {
		return nil, errors.New("query is required (or set persisted_query_hash)")
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "POST"
	}
	c := call{Method: method, URL: u.String(), Headers: in.Headers,
		Defaults: map[string]string{"Accept": "application/graphql-response+json, application/json;q=0.9"}}

	var uploaded []types.FileInfo
	var finishUploads func() []types.FileInfo
	switch method {
	case "GET":
		if len(in.Files) > 0 {
			return nil, errors.New("file uploads need method POST")
		}
		c.URL, err = op.GetURL(u.String())
		if err != nil {
			return nil, err
		}
	case "POST":
		if len(in.Files) > 0 {
			body, ct, fin, err := multipartBody(d, op, in.Files)
			if err != nil {
				return nil, err
			}
			defer body.Close()
			c.Body, c.ContentType, finishUploads = body, ct, fin
			// Apollo Server's CSRF prevention rejects multipart requests
			// without a preflight-forcing header.
			c.Defaults["Apollo-Require-Preflight"] = "true"
		} else {
			b, err := json.Marshal(op)
			if err != nil {
				return nil, fmt.Errorf("encoding request: %w", err)
			}
			c.Body, c.ContentType = bytes.NewReader(b), "application/json"
		}
	default:
		return nil, fmt.Errorf("method must be POST or GET, got %q", in.Method)
	}

	resp, err := do(ctx, d, in.HTTPOptions, in.Auth, c)
	if finishUploads != nil {
		uploaded = finishUploads()
	}
	if err != nil {
		return nil, err
	}
	out := graphqlOut{httpSummary: summarize(resp, in.IncludeHeaders), Uploaded: uploaded}
	body := rawBody(resp)
	if gr, ok := graphqlx.ParseResponse(body); ok {
		out.Data, out.Errors, out.Extensions = gr.Data, gr.Errors, gr.Extensions
		if len(out.Data) == 0 {
			out.Data = json.RawMessage("null")
		}
	} else {
		out.Data = json.RawMessage("null")
		out.Body = resp.Body
		out.Warnings = append(out.Warnings, "response is not a GraphQL result object; raw body returned")
	}
	if resp.Truncated {
		out.Warnings = append(out.Warnings, "response truncated: raise max_response_bytes or select fewer fields")
	}
	return out, nil
}

// multipartBody opens the files (checking policy and size up front) and
// returns a streaming multipart body. fin returns the per-file name, size
// and sha256 once the body has been consumed.
func multipartBody(d *tools.Deps, op graphqlx.Request, files []graphqlFile) (io.ReadCloser, string, func() []types.FileInfo, error) {
	maxUpload := d.Cfg.UploadBytes(0)
	ups := make([]graphqlx.UploadFile, len(files))
	infos := make([]types.FileInfo, len(files))
	hashes := make([]uploadHash, len(files))
	var mu sync.Mutex
	for i, f := range files {
		paths := append([]string(nil), f.VariablePaths...)
		if f.VariablePath != "" {
			paths = append([]string{f.VariablePath}, paths...)
		}
		if len(paths) == 0 {
			return nil, "", nil, fmt.Errorf("files[%d]: variable_path is required (e.g. variables.file)", i)
		}
		for _, p := range paths {
			if !strings.HasPrefix(p, "variables.") {
				return nil, "", nil, fmt.Errorf("files[%d]: variable_path %q must start with \"variables.\"", i, p)
			}
		}
		// Validate access now so policy errors surface before sending.
		fh, st, err := d.Files.OpenRead(f.File, maxUpload)
		if err != nil {
			return nil, "", nil, fmt.Errorf("files[%d]: %w", i, err)
		}
		realPath := fh.Name()
		fh.Close()
		name := f.Filename
		if name == "" {
			name = filepath.Base(realPath)
		}
		ct := f.ContentType
		if ct == "" {
			ct = fileio.DetectContentType(realPath, nil)
		}
		infos[i] = types.FileInfo{Name: name, Path: realPath, SizeBytes: st.Size(), ContentType: ct}
		file := f.File
		ups[i] = graphqlx.UploadFile{Paths: paths, Name: name, ContentType: ct,
			Open: func() (io.ReadCloser, error) {
				r, _, err := d.Files.OpenRead(file, maxUpload)
				return r, err
			}}
	}
	// The multipart writer goroutine may still be running when the HTTP
	// response arrives (a server can answer before reading the whole body),
	// so the hash is published under mu only once a file is fully read.
	body, ct, err := graphqlx.Multipart(op, ups, func(i int, r io.Reader) io.Reader {
		return &uploadHasher{h: fileio.NewHashingReader(r), done: func(sum string, n int64) {
			mu.Lock()
			hashes[i] = uploadHash{sum: sum, n: n, ok: true}
			mu.Unlock()
		}}
	})
	if err != nil {
		return nil, "", nil, err
	}
	fin := func() []types.FileInfo {
		mu.Lock()
		defer mu.Unlock()
		out := make([]types.FileInfo, len(infos))
		for i, info := range infos {
			if h := hashes[i]; h.ok {
				info.SHA256 = h.sum
				info.SizeBytes = h.n
			}
			out[i] = info
		}
		return out
	}
	return body, ct, fin, nil
}

type uploadHash struct {
	sum string
	n   int64
	ok  bool
}

// uploadHasher hashes a file as it is streamed and reports the digest once
// the file has been read to EOF.
type uploadHasher struct {
	h    *fileio.HashingReader
	done func(sum string, n int64)
}

func (u *uploadHasher) Read(p []byte) (int, error) {
	n, err := u.h.Read(p)
	if err == io.EOF && u.done != nil {
		u.done(u.h.SHA256(), u.h.N())
		u.done = nil
	}
	return n, err
}

func graphqlIntrospect(ctx context.Context, d *tools.Deps, in introspectIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "sdl"
	}
	if format != "sdl" && format != "json" {
		return nil, fmt.Errorf("format must be sdl or json, got %q", in.Format)
	}
	b, _ := json.Marshal(graphqlx.Request{Query: graphqlx.IntrospectionQuery, OperationName: "IntrospectionQuery"})
	opts := in.HTTPOptions
	if opts.MaxResponseBytes == 0 {
		// Introspection results of large schemas easily exceed 1 MiB.
		opts.MaxResponseBytes = d.Cfg.MaxResponseBytes
	}
	// ReadOptions.MaxBytes is not clamped by httpx: clamp to the ceiling.
	opts.MaxResponseBytes = d.Cfg.ResponseBytes(opts.MaxResponseBytes)
	resp, err := do(ctx, d, opts, in.Auth, call{Method: "POST", URL: u.String(), Headers: in.Headers,
		Body: bytes.NewReader(b), ContentType: "application/json",
		Defaults: map[string]string{"Accept": "application/graphql-response+json, application/json;q=0.9"},
		Read:     httpx.ReadOptions{MaxBytes: opts.MaxResponseBytes}})
	if err != nil {
		return nil, err
	}
	out := introspectOut{Status: resp.Status, StatusText: resp.StatusText, TimingMS: resp.TimingMS, Warnings: resp.Warnings}
	if resp.Truncated {
		return nil, fmt.Errorf("introspection result (%d bytes) was truncated at %d bytes; raise max_response_bytes (server ceiling %d)", resp.SizeBytes, opts.MaxResponseBytes, d.Cfg.MaxResponseBytes)
	}
	gr, ok := graphqlx.ParseResponse(rawBody(resp))
	if !ok {
		out.Body = truncateString(resp.Body, 4096)
		out.Warnings = append(out.Warnings, "response is not a GraphQL result object")
		return out, nil
	}
	out.Errors = gr.Errors
	if len(gr.Data) == 0 || string(gr.Data) == "null" {
		out.Warnings = append(out.Warnings, "no schema returned; introspection may be disabled on this server")
		return out, nil
	}
	schema, err := graphqlx.DecodeSchema(gr.Data)
	if err != nil {
		return nil, err
	}
	out.Counts = schema.Counts()
	out.RootTypes = schema.RootTypes()
	if format == "json" {
		if in.TypeName != "" {
			t := schema.Type(in.TypeName)
			if t == nil {
				return nil, fmt.Errorf("type %q not found in schema", in.TypeName)
			}
			out.Schema, _ = json.Marshal(t)
		} else {
			out.Schema = gr.Data
		}
		return out, nil
	}
	sdl, err := graphqlx.PrintSDL(schema, graphqlx.PrintOptions{Descriptions: in.IncludeDescriptions, TypeName: in.TypeName})
	if err != nil {
		return nil, err
	}
	out.SDL = sdl
	return out, nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
