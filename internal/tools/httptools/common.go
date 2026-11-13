package httptools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// requestEcho describes what was sent, with secrets masked and file
// contents replaced by name/size/hash.
type requestEcho struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *bodySummary      `json:"body,omitempty"`
}

// bodySummary describes a request body without its contents.
type bodySummary struct {
	Kind        string           `json:"kind"`
	SizeBytes   int64            `json:"size_bytes"`
	SHA256      string           `json:"sha256,omitempty"`
	ContentType string           `json:"content_type,omitempty"`
	Files       []types.FileInfo `json:"files,omitempty"`
}

// httpResult is the result of the http_* request tools: the shared HTTP
// response shape plus optional request details.
type httpResult struct {
	*types.HTTPResponse
	UploadedFiles []types.FileInfo `json:"uploaded_files,omitempty"`
	Request       *requestEcho     `json:"request,omitempty"`
}

// normalizeMethod upper-cases and validates an HTTP method token.
func normalizeMethod(m, def string) (string, error) {
	m = strings.TrimSpace(m)
	if m == "" {
		return def, nil
	}
	m = strings.ToUpper(m)
	for _, r := range m {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return "", fmt.Errorf("invalid HTTP method %q", m)
		}
	}
	return m, nil
}

// buildURL parses rawURL and appends the query parameters (string, number,
// bool or list values). Keys are added in sorted order after any query
// already in the URL.
func buildURL(rawURL string, query map[string]any) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid url %q: an absolute http:// or https:// URL is required", rawURL)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (use http or https)", u.Scheme)
	}
	if len(query) == 0 {
		return u, nil
	}
	vals, err := toValues(query, "query")
	if err != nil {
		return nil, err
	}
	enc := encodeOrdered(vals)
	if u.RawQuery == "" {
		u.RawQuery = enc
	} else if enc != "" {
		u.RawQuery += "&" + enc
	}
	return u, nil
}

// nameValue is an ordered key/value pair.
type nameValue struct {
	Name  string
	Value string
}

// toValues converts a map of scalar-or-list values into ordered pairs
// (keys sorted).
func toValues(m map[string]any, what string) ([]nameValue, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []nameValue
	for _, k := range keys {
		vs, err := scalarList(m[k])
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", what, k, err)
		}
		for _, v := range vs {
			out = append(out, nameValue{k, v})
		}
	}
	return out, nil
}

// scalarList accepts a scalar or a list of scalars.
func scalarList(v any) ([]string, error) {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, err := scalar(e)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return x, nil
	default:
		s, err := scalar(v)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
}

func scalar(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case float64:
		return fmt.Sprint(x), nil
	case int, int64, float32, int32:
		return fmt.Sprint(x), nil
	default:
		return "", fmt.Errorf("value must be a string, number, boolean or a list of them (got %T)", v)
	}
}

func encodeOrdered(vals []nameValue) string {
	var sb strings.Builder
	for i, nv := range vals {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(url.QueryEscape(nv.Name))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(nv.Value))
	}
	return sb.String()
}

// applyHeaders sets user headers on req. A Host header overrides req.Host.
func applyHeaders(req *http.Request, h map[string]string) {
	for k, v := range h {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
}

func hasHeader(h map[string]string, name string) bool {
	for k := range h {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// echoRequest builds a redacted description of req.
func echoRequest(req *http.Request, body *bodySummary) *requestEcho {
	h := req.Header.Clone()
	if req.Host != "" && req.Host != req.URL.Host {
		h.Set("Host", req.Host)
	}
	return &requestEcho{
		Method:  req.Method,
		URL:     redact.URL(req.URL.String()),
		Headers: redact.Headers(h),
		Body:    body,
	}
}

// execute sends req with timing and shapes the response. When ro.SaveTo is
// set but the server answers with an error status, the body is returned
// inline instead of being written to disk.
func execute(c *httpx.Client, req *http.Request, ro httpx.ReadOptions) (*types.HTTPResponse, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent())
	}
	req, tr := httpx.WithTrace(req)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, describeErr(c, err)
	}
	defer resp.Body.Close()
	var warn string
	if ro.SaveTo != "" && resp.StatusCode >= 400 {
		warn = fmt.Sprintf("response status %d: body returned inline and not saved to %s", resp.StatusCode, ro.SaveTo)
		ro.SaveTo = ""
	}
	out, err := c.ReadResponse(resp, tr, ro)
	if err != nil {
		return nil, describeErr(c, err)
	}
	if warn != "" {
		out.Warnings = append(out.Warnings, warn)
	}
	return out, nil
}

// describeErr makes transport errors actionable.
func describeErr(c *httpx.Client, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || httpx.IsTimeout(err) {
		return fmt.Errorf("request timed out after %s (raise timeout_seconds): %w", c.Timeout, err)
	}
	return err
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// fileBody streams a file from disk as a request body. Every Open re-opens
// the file (for redirects, auth retries and upload retries) and hashes what
// is actually read.
type fileBody struct {
	files *fileio.Policy
	path  string
	max   int64
	info  types.FileInfo
	wrap  func(io.Reader) io.Reader

	mu   sync.Mutex
	last *fileio.HashingReader
}

// newFileBody stats the file through the policy.
func newFileBody(files *fileio.Policy, path string, maxBytes int64) (*fileBody, error) {
	f, st, err := files.OpenRead(path, maxBytes)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	f.Close()
	return &fileBody{
		files: files,
		path:  path,
		max:   maxBytes,
		info: types.FileInfo{
			Name:        st.Name(),
			Path:        f.Name(),
			SizeBytes:   st.Size(),
			ContentType: fileio.DetectContentType(st.Name(), head[:n]),
		},
	}, nil
}

// Open returns a fresh reader positioned at the start of the file.
func (b *fileBody) Open() (io.ReadCloser, error) {
	f, st, err := b.files.OpenRead(b.path, b.max)
	if err != nil {
		return nil, err
	}
	if st.Size() != b.info.SizeBytes {
		f.Close()
		return nil, fmt.Errorf("%s changed size while uploading (%d -> %d bytes)", b.info.Name, b.info.SizeBytes, st.Size())
	}
	hr := fileio.NewHashingReader(f)
	b.mu.Lock()
	b.last = hr
	b.mu.Unlock()
	var r io.Reader = hr
	if b.wrap != nil {
		r = b.wrap(r)
	}
	return readCloser{r, f}, nil
}

// Sent returns the bytes read and their SHA-256 for the latest attempt.
func (b *fileBody) Sent() (int64, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return 0, ""
	}
	return b.last.N(), b.last.SHA256()
}

// Info returns the file description, with the hash when the file was sent
// completely.
func (b *fileBody) Info() types.FileInfo {
	info := b.info
	if info.SizeBytes == 0 {
		info.SHA256 = emptySHA256
	} else if n, sum := b.Sent(); n == info.SizeBytes {
		info.SHA256 = sum
	}
	return info
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }
