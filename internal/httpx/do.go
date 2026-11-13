package httpx

import (
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Trace records connection timing for one request.
type Trace struct {
	mu                  sync.Mutex
	start               time.Time
	dnsStart, dnsDone   time.Time
	connStart, connDone time.Time
	tlsStart, tlsDone   time.Time
	firstByte           time.Time
	TLS                 *tls.ConnectionState
}

// WithTrace attaches a timing trace to req.
func WithTrace(req *http.Request) (*http.Request, *Trace) {
	t := &Trace{start: time.Now()}
	ct := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { t.set(&t.dnsStart) },
		DNSDone:  func(httptrace.DNSDoneInfo) { t.set(&t.dnsDone) },
		ConnectStart: func(string, string) {
			t.mu.Lock()
			if t.connStart.IsZero() {
				t.connStart = time.Now()
			}
			t.mu.Unlock()
		},
		ConnectDone:       func(string, string, error) { t.set(&t.connDone) },
		TLSHandshakeStart: func() { t.set(&t.tlsStart) },
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) {
			t.set(&t.tlsDone)
			t.mu.Lock()
			t.TLS = &cs
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() { t.set(&t.firstByte) },
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), ct)), t
}

func (t *Trace) set(p *time.Time) {
	t.mu.Lock()
	*p = time.Now()
	t.mu.Unlock()
}

func span(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return 0
	}
	return types.MS(b.Sub(a))
}

// Timing returns the breakdown, with total measured until now.
func (t *Trace) Timing() types.Timing {
	t.mu.Lock()
	defer t.mu.Unlock()
	return types.Timing{
		DNS:     span(t.dnsStart, t.dnsDone),
		Connect: span(t.connStart, t.connDone),
		TLS:     span(t.tlsStart, t.tlsDone),
		TTFB:    span(t.start, t.firstByte),
		Total:   types.MS(time.Since(t.start)),
	}
}

// ReadOptions control how a response body is consumed.
type ReadOptions struct {
	// MaxBytes is the inline body limit (0 = client default).
	MaxBytes int64
	// SaveTo streams the body to this path instead of returning it inline.
	SaveTo    string
	Overwrite bool
	// MaxDownload bounds SaveTo downloads (0 = server default).
	MaxDownload int64
	// Progress, when set, is called while saving with bytes written so far.
	Progress func(done, total int64)
}

// Do executes req with timing and converts the response to the shared
// HTTP response shape. The request context should already carry a deadline.
func (c *Client) Do(req *http.Request, ro ReadOptions) (*types.HTTPResponse, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent())
	}
	req, tr := WithTrace(req)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := c.ReadResponse(resp, tr, ro)
	return out, err
}

// ReadResponse converts an already-received response. tr may be nil.
func (c *Client) ReadResponse(resp *http.Response, tr *Trace, ro ReadOptions) (*types.HTTPResponse, error) {
	out := &types.HTTPResponse{
		Status:      resp.StatusCode,
		StatusText:  strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode))),
		Headers:     FlattenHeaders(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		FinalURL:    resp.Request.URL.String(),
		Protocol:    resp.Proto,
		Redirects:   c.Redirects,
	}
	if out.StatusText == "" {
		out.StatusText = http.StatusText(resp.StatusCode)
	}
	if resp.TLS != nil {
		out.TLS = tlsx.Info(resp.TLS, c.Insecure)
	} else if tr != nil && tr.TLS != nil {
		out.TLS = tlsx.Info(tr.TLS, c.Insecure)
	}
	if c.Insecure {
		out.Warnings = append(out.Warnings, "TLS certificate verification was disabled (insecure_skip_verify)")
	}

	body, enc := decodedBody(resp)
	if enc != "" {
		out.Warnings = append(out.Warnings, "response is "+enc+"-encoded and could not be decompressed; body is raw")
	}

	if ro.SaveTo != "" {
		maxDl := c.factory.Cfg.DownloadBytes(ro.MaxDownload)
		w, err := c.factory.Files.CreateWrite(ro.SaveTo, ro.Overwrite, maxDl)
		if err != nil {
			return nil, err
		}
		var src io.Reader = body
		if ro.Progress != nil {
			src = &progressReader{r: body, total: resp.ContentLength, fn: ro.Progress}
		}
		if _, err := io.Copy(w, src); err != nil {
			w.Abort()
			return nil, fmt.Errorf("saving response: %w", err)
		}
		info, err := w.Commit()
		if err != nil {
			return nil, err
		}
		if out.ContentType != "" {
			info.ContentType = out.ContentType
		}
		out.SavedTo = &info
		out.SizeBytes = info.SizeBytes
		out.BodyEncoding = "none"
		if tr != nil {
			out.TimingMS = tr.Timing()
		}
		return out, nil
	}

	// c.MaxResponseBytes is the per-call value already clamped to the
	// server ceiling; a ReadOptions override must be clamped the same way.
	max := c.MaxResponseBytes
	if ro.MaxBytes > 0 {
		if c.factory != nil {
			max = c.factory.Cfg.ResponseBytes(ro.MaxBytes)
		} else {
			max = min(ro.MaxBytes, c.MaxResponseBytes)
		}
	}
	data, total, truncated, err := ReadLimited(body, max)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	out.Body, out.BodyEncoding = types.EncodeBody(data, out.ContentType)
	out.SizeBytes = total
	out.Truncated = truncated
	if truncated {
		out.Warnings = append(out.Warnings, fmt.Sprintf("body truncated to %d bytes; use save_to to download it fully or raise max_response_bytes", max))
	}
	if tr != nil {
		out.TimingMS = tr.Timing()
	}
	return out, nil
}

// ReadLimited reads up to max bytes and drains (counting) up to 64 MiB more
// so the total size can be reported.
func ReadLimited(r io.Reader, max int64) (data []byte, total int64, truncated bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, max))
	if err != nil {
		return data, int64(len(data)), false, err
	}
	total = int64(len(data))
	extra, _ := io.Copy(io.Discard, io.LimitReader(r, 64<<20))
	if extra > 0 {
		truncated = true
		total += extra
	}
	return data, total, truncated, nil
}

// decodedBody decompresses gzip/deflate bodies that the transport left
// compressed (because the caller set Accept-Encoding). It returns the raw
// encoding name if it could not decode it.
func decodedBody(resp *http.Response) (io.Reader, string) {
	if resp.Uncompressed {
		return resp.Body, ""
	}
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return resp.Body, ""
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return resp.Body, "gzip"
		}
		return zr, ""
	case "deflate":
		return flate.NewReader(resp.Body), ""
	default:
		return resp.Body, resp.Header.Get("Content-Encoding")
	}
}

type progressReader struct {
	r     io.Reader
	n     int64
	total int64
	fn    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if n > 0 {
		p.fn(p.n, p.total)
	}
	return n, err
}

// FlattenHeaders converts headers to a single-valued map. Repeated values
// are joined with ", " (Set-Cookie with "\n").
func FlattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sep := ", "
		if strings.EqualFold(k, "Set-Cookie") {
			sep = "\n"
		}
		out[k] = strings.Join(h[k], sep)
	}
	return out
}

// IsTimeout reports whether err is a timeout.
func IsTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}
