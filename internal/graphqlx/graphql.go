// Package graphqlx implements GraphQL over HTTP: request encoding (POST,
// GET and the multipart file-upload spec), response parsing, schema
// introspection with an SDL printer, and subscriptions over
// graphql-transport-ws, subscriptions-transport-ws and graphql-sse.
package graphqlx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

// Request is a GraphQL operation.
type Request struct {
	Query         string         `json:"query,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
	OperationName string         `json:"operationName,omitempty"`
	Extensions    map[string]any `json:"extensions,omitempty"`
}

// Response is a GraphQL execution result. Fields are kept as raw JSON so
// numbers and key order survive.
type Response struct {
	Data       json.RawMessage `json:"data,omitempty"`
	Errors     json.RawMessage `json:"errors,omitempty"`
	Extensions json.RawMessage `json:"extensions,omitempty"`
}

// ParseResponse parses a GraphQL JSON response body. ok is false when the
// body is not a GraphQL result object.
func ParseResponse(body []byte) (*Response, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false
	}
	_, hasData := m["data"]
	_, hasErrors := m["errors"]
	if !hasData && !hasErrors {
		return nil, false
	}
	return &Response{Data: m["data"], Errors: m["errors"], Extensions: m["extensions"]}, true
}

// PersistedQuery adds the Apollo automatic-persisted-query extension.
func (r *Request) PersistedQuery(sha256Hash string) {
	if sha256Hash == "" {
		return
	}
	if r.Extensions == nil {
		r.Extensions = map[string]any{}
	}
	r.Extensions["persistedQuery"] = map[string]any{"version": 1, "sha256Hash": sha256Hash}
}

// GetURL encodes the operation as query parameters for GET requests
// (GraphQL over HTTP spec: query, variables, operationName, extensions).
func (r *Request) GetURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if r.Query != "" {
		q.Set("query", r.Query)
	}
	if len(r.Variables) > 0 {
		b, err := json.Marshal(r.Variables)
		if err != nil {
			return "", err
		}
		q.Set("variables", string(b))
	}
	if r.OperationName != "" {
		q.Set("operationName", r.OperationName)
	}
	if len(r.Extensions) > 0 {
		b, err := json.Marshal(r.Extensions)
		if err != nil {
			return "", err
		}
		q.Set("extensions", string(b))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// UploadFile is one file in a multipart request.
type UploadFile struct {
	// Paths are object paths in the operations document where the file
	// goes, e.g. "variables.file" or "variables.files.0".
	Paths       []string
	Name        string // filename sent in the part
	ContentType string
	Open        func() (io.ReadCloser, error)
}

// SetNullAtPath sets the value at a dotted path ("variables.files.0") to
// null, creating intermediate objects/arrays as needed. The root is the
// operations object (with "variables" etc.).
func SetNullAtPath(root map[string]any, path string) error {
	parts := strings.Split(path, ".")
	if len(parts) < 2 || parts[0] == "" {
		return fmt.Errorf("invalid variable path %q (expected e.g. variables.file or variables.files.0)", path)
	}
	var cur any = root
	for i, p := range parts {
		last := i == len(parts)-1
		nextIsIndex := false
		if !last {
			_, err := strconv.Atoi(parts[i+1])
			nextIsIndex = err == nil
		}
		newContainer := func() any {
			if nextIsIndex {
				return []any{}
			}
			return map[string]any{}
		}
		switch c := cur.(type) {
		case map[string]any:
			if last {
				c[p] = nil
				return nil
			}
			child, ok := c[p]
			if !ok || child == nil {
				child = newContainer()
				c[p] = child
			}
			// Slices may be re-allocated when growing; write back after.
			if s, ok := child.([]any); ok && nextIsIndex {
				idx, _ := strconv.Atoi(parts[i+1])
				for len(s) <= idx {
					s = append(s, nil)
				}
				c[p] = s
				child = s
			}
			cur = child
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(c) {
				return fmt.Errorf("variable path %q: bad index %q", path, p)
			}
			if last {
				c[idx] = nil
				return nil
			}
			child := c[idx]
			if child == nil {
				child = newContainer()
			}
			if s, ok := child.([]any); ok && nextIsIndex {
				n, _ := strconv.Atoi(parts[i+1])
				for len(s) <= n {
					s = append(s, nil)
				}
				child = s
			}
			c[idx] = child
			cur = child
		default:
			return fmt.Errorf("variable path %q: %q is not an object or list", path, strings.Join(parts[:i], "."))
		}
	}
	return nil
}

// Multipart builds a GraphQL multipart request
// (https://github.com/jaydenseric/graphql-multipart-request-spec) that is
// streamed through an io.Pipe: file contents are never buffered. The
// returned reader must be consumed (or closed) by the HTTP client. wrap, when
// set, wraps each file reader (e.g. for hashing and counting).
func Multipart(op Request, files []UploadFile, wrap func(i int, r io.Reader) io.Reader) (body io.ReadCloser, contentType string, err error) {
	if len(files) == 0 {
		return nil, "", errors.New("no files")
	}
	ops := map[string]any{"query": op.Query}
	if op.OperationName != "" {
		ops["operationName"] = op.OperationName
	}
	if op.Extensions != nil {
		ops["extensions"] = op.Extensions
	}
	vars := map[string]any{}
	for k, v := range op.Variables {
		vars[k] = v
	}
	ops["variables"] = vars
	fmap := map[string][]string{}
	for i, f := range files {
		if len(f.Paths) == 0 {
			return nil, "", fmt.Errorf("file %d: no variable path", i)
		}
		for _, p := range f.Paths {
			if err := SetNullAtPath(ops, p); err != nil {
				return nil, "", err
			}
		}
		fmap[strconv.Itoa(i)] = f.Paths
	}
	opsJSON, err := json.Marshal(ops)
	if err != nil {
		return nil, "", fmt.Errorf("operations: %w", err)
	}
	mapJSON, err := json.Marshal(fmap)
	if err != nil {
		return nil, "", err
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			if err := mw.WriteField("operations", string(opsJSON)); err != nil {
				return err
			}
			if err := mw.WriteField("map", string(mapJSON)); err != nil {
				return err
			}
			for i, f := range files {
				h := textproto.MIMEHeader{}
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%d"; filename="%s"`, i, escapeQuotes(f.Name)))
				ct := f.ContentType
				if ct == "" {
					ct = "application/octet-stream"
				}
				h.Set("Content-Type", ct)
				w, err := mw.CreatePart(h)
				if err != nil {
					return err
				}
				rc, err := f.Open()
				if err != nil {
					return err
				}
				var r io.Reader = rc
				if wrap != nil {
					r = wrap(i, rc)
				}
				_, err = io.Copy(w, r)
				rc.Close()
				if err != nil {
					return err
				}
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	return pr, mw.FormDataContentType(), nil
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string { return quoteEscaper.Replace(s) }
