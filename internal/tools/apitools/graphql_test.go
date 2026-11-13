package apitools_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type gqlOut struct {
	Status        int               `json:"status"`
	ContentType   string            `json:"content_type"`
	Headers       map[string]string `json:"headers"`
	Data          json.RawMessage   `json:"data"`
	Errors        json.RawMessage   `json:"errors"`
	Extensions    json.RawMessage   `json:"extensions"`
	Body          string            `json:"body"`
	Warnings      []string          `json:"warnings"`
	UploadedFiles []struct {
		Name        string `json:"name"`
		SizeBytes   int64  `json:"size_bytes"`
		SHA256      string `json:"sha256"`
		ContentType string `json:"content_type"`
	} `json:"uploaded_files"`
}

type gqlReq struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
	Extensions    map[string]any `json:"extensions"`
}

// gqlServer answers POST JSON and GET operations, echoing what it got.
func gqlServer(t *testing.T) string {
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		var op gqlReq
		switch r.Method {
		case http.MethodGet:
			q := r.URL.Query()
			op.Query = q.Get("query")
			op.OperationName = q.Get("operationName")
			if v := q.Get("variables"); v != "" {
				json.Unmarshal([]byte(v), &op.Variables)
			}
			if v := q.Get("extensions"); v != "" {
				json.Unmarshal([]byte(v), &op.Extensions)
			}
		case http.MethodPost:
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "bad content type", 415)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		switch {
		case strings.Contains(op.Query, "boom"):
			w.Header().Set("Content-Type", "application/graphql-response+json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"data":   map[string]any{"boom": nil},
				"errors": []any{map[string]any{"message": "boom failed", "path": []any{"boom"}, "extensions": map[string]any{"code": "INTERNAL"}}},
			})
		case strings.Contains(op.Query, "invalid"):
			w.Header().Set("Content-Type", "application/graphql-response+json")
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"message": "Cannot query field \"invalid\""}}})
		case op.Query == "" && op.Extensions != nil:
			writeJSON(w, map[string]any{"errors": []any{map[string]any{"message": "PersistedQueryNotFound"}},
				"extensions": map[string]any{"seen": op.Extensions}})
		default:
			writeJSON(w, map[string]any{
				"data": map[string]any{"echo": map[string]any{
					"method": r.Method, "query": op.Query, "variables": op.Variables,
					"operationName": op.OperationName, "accept": r.Header.Get("Accept"),
					"x": r.Header.Get("X-Test"),
				}},
				"extensions": map[string]any{"cost": 3},
			})
		}
	})
	return srv.URL
}

func TestGraphQLRequestPOST(t *testing.T) {
	h := newHarness(t)
	url := gqlServer(t)
	r := decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{
		"url":             url,
		"query":           "query Q($id: ID!) { user(id: $id) { name } }",
		"variables":       map[string]any{"id": "42", "n": 7},
		"operation_name":  "Q",
		"headers":         map[string]string{"X-Test": "yes"},
		"include_headers": true,
	}))
	if r.Status != 200 || r.Errors != nil {
		t.Fatalf("status %d errors %s", r.Status, r.Errors)
	}
	var data struct {
		Echo struct {
			Method, Query, OperationName, Accept, X string
			Variables                               map[string]any
		}
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		t.Fatal(err)
	}
	e := data.Echo
	if e.Method != "POST" || e.OperationName != "Q" || e.Variables["id"] != "42" || e.Variables["n"] != float64(7) || e.X != "yes" {
		t.Fatalf("echo %+v", e)
	}
	mustContain(t, e.Accept, "application/graphql-response+json")
	if string(r.Extensions) != `{"cost":3}` {
		t.Fatalf("extensions %s", r.Extensions)
	}
	if r.Headers["Content-Type"] == "" {
		t.Fatalf("include_headers: %v", r.Headers)
	}
}

func TestGraphQLRequestErrorsAreResults(t *testing.T) {
	h := newHarness(t)
	url := gqlServer(t)
	r := decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{"url": url, "query": "{ boom }"}))
	if r.Status != 200 || string(r.Data) != `{"boom":null}` {
		t.Fatalf("status %d data %s", r.Status, r.Data)
	}
	mustContain(t, string(r.Errors), "boom failed", "INTERNAL")

	// HTTP 400 with a GraphQL error body is still a result.
	r = decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{"url": url, "query": "{ invalid }"}))
	if r.Status != 400 || string(r.Data) != "null" {
		t.Fatalf("status %d data %s", r.Status, r.Data)
	}
	mustContain(t, string(r.Errors), "Cannot query field")
}

func TestGraphQLRequestGETAndPersisted(t *testing.T) {
	h := newHarness(t)
	url := gqlServer(t)
	r := decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{
		"url": url, "method": "get", "query": "{ me { id } }", "variables": map[string]any{"a": 1},
	}))
	mustContain(t, string(r.Data), `"method":"GET"`, `"query":"{ me { id } }"`, `"variables":{"a":1}`)

	r = decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{
		"url": url, "method": "GET", "persisted_query_hash": "abc123",
	}))
	mustContain(t, string(r.Errors), "PersistedQueryNotFound")
	mustContain(t, string(r.Extensions), `"sha256Hash":"abc123"`, `"version":1`)
}

func TestGraphQLRequestNonGraphQLBody(t *testing.T) {
	h := newHarness(t)
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(502)
		io.WriteString(w, "<h1>Bad gateway</h1>")
	})
	r := decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{"url": srv.URL, "query": "{ a }"}))
	if r.Status != 502 || r.Body != "<h1>Bad gateway</h1>" || string(r.Data) != "null" || len(r.Warnings) == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestGraphQLRequestValidation(t *testing.T) {
	h := newHarness(t)
	h.MustFail("graphql_request", map[string]any{"url": "http://127.0.0.1:1/"}, "query is required")
	h.MustFail("graphql_request", map[string]any{"url": "ftp://x/", "query": "{a}"}, "unsupported URL scheme")
	h.MustFail("graphql_request", map[string]any{"url": "http://127.0.0.1:1/", "query": "{a}", "method": "PUT"}, "method must be POST or GET")
	p := h.WriteInput("a.txt", []byte("x"))
	h.MustFail("graphql_request", map[string]any{"url": "http://127.0.0.1:1/", "query": "{a}", "method": "GET",
		"files": []any{map[string]any{"variable_path": "variables.file", "file": p}}}, "need method POST")
	h.MustFail("graphql_request", map[string]any{"url": "http://127.0.0.1:1/", "query": "{a}",
		"files": []any{map[string]any{"variable_path": "file", "file": p}}}, "must start with")
	h.MustFail("graphql_request", map[string]any{"url": "http://127.0.0.1:1/", "query": "{a}",
		"files": []any{map[string]any{"variable_path": "variables.file", "file": "/definitely/not/allowed.txt"}}}, "")
}

func TestGraphQLMultipartUpload(t *testing.T) {
	h := newHarness(t)
	big := pattern(3<<20 + 17)
	small := []byte("hello avatar")
	pBig := h.WriteInput("big.bin", big)
	pSmall := h.WriteInput("avatar.png", small)

	type part struct {
		Field, Filename, ContentType, SHA string
		Size                              int64
	}
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Apollo-Require-Preflight") != "true" {
			http.Error(w, "csrf", 400)
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var ops, fmap json.RawMessage
		var parts []part
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			switch p.FormName() {
			case "operations":
				ops, _ = io.ReadAll(p)
			case "map":
				fmap, _ = io.ReadAll(p)
			default:
				hs := sha256.New()
				n, _ := io.Copy(hs, p)
				parts = append(parts, part{p.FormName(), p.FileName(), p.Header.Get("Content-Type"), hex.EncodeToString(hs.Sum(nil)), n})
			}
		}
		writeJSON(w, map[string]any{"data": map[string]any{"operations": ops, "map": fmap, "parts": parts}})
	})

	r := decode[gqlOut](t, h.MustOK("graphql_request", map[string]any{
		"url":       srv.URL,
		"query":     "mutation($file: Upload!, $docs: [Upload!]!, $userId: ID!) { up(file: $file, docs: $docs, userId: $userId) }",
		"variables": map[string]any{"userId": "u1"},
		"files": []any{
			map[string]any{"variable_path": "variables.file", "file": pSmall},
			map[string]any{"variable_paths": []string{"variables.docs.0", "variables.docs.1"}, "file": pBig, "filename": "renamed.bin", "content_type": "application/x-test"},
		},
	}))
	if r.Status != 200 {
		t.Fatalf("status %d body %s errors %s", r.Status, r.Body, r.Errors)
	}
	var data struct {
		Operations struct {
			Query     string
			Variables map[string]any
		}
		Map   map[string][]string
		Parts []part
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		t.Fatalf("%v: %s", err, r.Data)
	}
	v := data.Operations.Variables
	if v["userId"] != "u1" || v["file"] != nil {
		t.Fatalf("variables %v", v)
	}
	if _, ok := v["file"]; !ok {
		t.Fatalf("variables.file missing: %v", v)
	}
	if docs, _ := v["docs"].([]any); len(docs) != 2 || docs[0] != nil || docs[1] != nil {
		t.Fatalf("docs %v", v["docs"])
	}
	if strings.Join(data.Map["0"], ",") != "variables.file" || strings.Join(data.Map["1"], ",") != "variables.docs.0,variables.docs.1" {
		t.Fatalf("map %v", data.Map)
	}
	if len(data.Parts) != 2 {
		t.Fatalf("parts %+v", data.Parts)
	}
	p0, p1 := data.Parts[0], data.Parts[1]
	if p0.Field != "0" || p0.Filename != "avatar.png" || p0.ContentType != "image/png" || p0.SHA != sha(small) || p0.Size != int64(len(small)) {
		t.Fatalf("part 0 %+v", p0)
	}
	if p1.Field != "1" || p1.Filename != "renamed.bin" || p1.ContentType != "application/x-test" || p1.SHA != sha(big) || p1.Size != int64(len(big)) {
		t.Fatalf("part 1 %+v", p1)
	}
	if len(r.UploadedFiles) != 2 {
		t.Fatalf("uploaded_files %+v", r.UploadedFiles)
	}
	u0, u1 := r.UploadedFiles[0], r.UploadedFiles[1]
	if u0.Name != "avatar.png" || u0.SHA256 != sha(small) || u0.SizeBytes != int64(len(small)) {
		t.Fatalf("uploaded 0 %+v", u0)
	}
	if u1.Name != "renamed.bin" || u1.SHA256 != sha(big) || u1.SizeBytes != int64(len(big)) || u1.ContentType != "application/x-test" {
		t.Fatalf("uploaded 1 %+v", u1)
	}
}

// A server that rejects the upload early must not hang the call.
func TestGraphQLMultipartEarlyReject(t *testing.T) {
	h := newHarness(t)
	p := h.WriteInput("big.bin", pattern(8<<20))
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(413)
		writeJSON(w, map[string]any{"errors": []any{map[string]any{"message": "too large"}}})
	})
	timed(t, 15e9, func() {
		r := h.Call("graphql_request", map[string]any{
			"url": srv.URL, "query": "mutation($f: Upload!) { up(f: $f) }",
			"files": []any{map[string]any{"variable_path": "variables.f", "file": p}},
		})
		if !r.IsError {
			var out gqlOut
			r.Decode(t, &out)
			if out.Status != 413 {
				t.Fatalf("status %d", out.Status)
			}
		}
	})
}

func introspectionServer(t *testing.T, body []byte) string {
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		var op gqlReq
		json.NewDecoder(r.Body).Decode(&op)
		if op.OperationName != "IntrospectionQuery" || !strings.Contains(op.Query, "__schema") {
			http.Error(w, "unexpected query", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	return srv.URL
}

type introOut struct {
	Status    int               `json:"status"`
	SDL       string            `json:"sdl"`
	Schema    json.RawMessage   `json:"schema"`
	Counts    map[string]int    `json:"type_counts"`
	RootTypes map[string]string `json:"root_types"`
	Errors    json.RawMessage   `json:"errors"`
	Body      string            `json:"body"`
	Warnings  []string          `json:"warnings"`
}

func TestGraphQLIntrospect(t *testing.T) {
	h := newHarness(t)
	url := introspectionServer(t, testdata(t, "graphqlx/testdata/introspection.json"))
	want := strings.ReplaceAll(string(testdata(t, "graphqlx/testdata/schema.graphql")), "\r\n", "\n")

	r := decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url}))
	if r.Status != 200 || r.SDL != want {
		t.Fatalf("status %d sdl:\n%s\nwant:\n%s", r.Status, r.SDL, want)
	}
	if r.RootTypes["query"] != "Query" || r.RootTypes["subscription"] != "Subscription" || len(r.Counts) == 0 {
		t.Fatalf("roots %v counts %v", r.RootTypes, r.Counts)
	}

	wantDesc := strings.ReplaceAll(string(testdata(t, "graphqlx/testdata/schema_descriptions.graphql")), "\r\n", "\n")
	r = decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url, "include_descriptions": true}))
	if r.SDL != wantDesc {
		t.Fatalf("descriptions sdl:\n%s", r.SDL)
	}

	r = decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url, "type_name": "Query"}))
	mustContain(t, r.SDL, "type Query {", "node(id: ID!): Node")
	mustNotContain(t, r.SDL, "type Mutation")

	r = decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url, "format": "json"}))
	mustContain(t, string(r.Schema), `"__schema"`, `"queryType"`)
	r = decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url, "format": "json", "type_name": "Query"}))
	mustContain(t, string(r.Schema), `"Query"`)
	mustNotContain(t, string(r.Schema), `"__schema"`)

	h.MustFail("graphql_introspect", map[string]any{"url": url, "type_name": "Nope"}, "")
	h.MustFail("graphql_introspect", map[string]any{"url": url, "format": "json", "type_name": "Nope"}, "not found")
	h.MustFail("graphql_introspect", map[string]any{"url": url, "format": "yaml"}, "format must be")
}

func TestGraphQLIntrospectDisabled(t *testing.T) {
	h := newHarness(t)
	url := introspectionServer(t, []byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
	r := decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": url}))
	mustContain(t, string(r.Errors), "introspection is not allowed")
	if r.SDL != "" || len(r.Warnings) == 0 {
		t.Fatalf("%+v", r)
	}

	srv := server(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 404) })
	r = decode[introOut](t, h.MustOK("graphql_introspect", map[string]any{"url": srv.URL}))
	if r.Status != 404 || !strings.Contains(r.Body, "nope") {
		t.Fatalf("%+v", r)
	}
}
