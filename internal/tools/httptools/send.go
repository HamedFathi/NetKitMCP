package httptools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// DownloadOptions are shared by the tools that can save the response.
type DownloadOptions struct {
	SaveTo           string `json:"save_to,omitempty" jsonschema:"stream the response body to this file (inside an allowed write directory) instead of returning it inline; reports name, size and sha256"`
	Overwrite        bool   `json:"overwrite,omitempty" jsonschema:"allow save_to to replace an existing file (default false)"`
	MaxDownloadBytes int64  `json:"max_download_bytes,omitempty" jsonschema:"size limit for save_to downloads (default 1 GiB, capped by server policy)"`
}

// bodySource produces a request body. A nil source means no body.
type bodySource struct {
	// open returns a fresh body reader; it is also used as GetBody.
	open func() (io.ReadCloser, error)
	// size is the body length (-1 when unknown, which means chunked).
	size        int64
	contentType string
	summary     *bodySummary
	// finish fills in post-send details (hashes) on the summary and
	// returns the uploaded files to report.
	finish func() []types.FileInfo
}

func bytesSource(data []byte, kind, contentType string) *bodySource {
	return &bodySource{
		open:        func() (io.ReadCloser, error) { return io.NopCloser(bytesReader(data)), nil },
		size:        int64(len(data)),
		contentType: contentType,
		summary:     &bodySummary{Kind: kind, SizeBytes: int64(len(data)), SHA256: sha256Hex(data), ContentType: contentType},
	}
}

func fileSource(fb *fileBody) *bodySource {
	sum := &bodySummary{Kind: "file", SizeBytes: fb.info.SizeBytes, ContentType: fb.info.ContentType}
	return &bodySource{
		open:        fb.Open,
		size:        fb.info.SizeBytes,
		contentType: fb.info.ContentType,
		summary:     sum,
		finish: func() []types.FileInfo {
			info := fb.Info()
			sum.SHA256 = info.SHA256
			sum.Files = []types.FileInfo{info}
			return []types.FileInfo{info}
		},
	}
}

// sendSpec is one fully described HTTP request.
type sendSpec struct {
	method         string
	url            *url.URL
	headers        map[string]string
	body           *bodySource
	download       DownloadOptions
	includeRequest bool
	opts           types.HTTPOptions
	auth           *auth.Config
	warnings       []string
}

// send builds a client, executes the request and shapes the result.
func send(ctx context.Context, mreq *mcp.CallToolRequest, d *tools.Deps, s sendSpec) (*httpResult, error) {
	c, err := d.NewHTTPClient(s.opts, s.auth)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rctx, cancel := c.Context(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, s.method, s.url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	applyHeaders(req, s.headers)
	rep := progress.FromRequest(mreq)
	if b := s.body; b != nil {
		if b.contentType != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", b.contentType)
		}
		open := b.open
		if rep.Enabled() && b.size > 0 {
			open = func() (io.ReadCloser, error) {
				rc, err := b.open()
				if err != nil {
					return nil, err
				}
				return readCloser{rep.Reader(ctx, rc, b.size, "uploading request body"), rc}, nil
			}
		}
		if b.size == 0 {
			req.Body = http.NoBody
			req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		} else {
			rc, err := open()
			if err != nil {
				return nil, err
			}
			req.Body = rc
			req.GetBody = open
			req.ContentLength = b.size
		}
	}

	ro := httpx.ReadOptions{
		SaveTo:      s.download.SaveTo,
		Overwrite:   s.download.Overwrite,
		MaxDownload: s.download.MaxDownloadBytes,
	}
	if ro.SaveTo != "" && rep.Enabled() {
		ro.Progress = rep.Func(ctx, "downloading")
	}
	resp, err := execute(c, req, ro)
	var files []types.FileInfo
	if s.body != nil && s.body.finish != nil {
		files = s.body.finish()
	}
	if err != nil {
		return nil, err
	}
	resp.Warnings = append(s.warnings, resp.Warnings...)
	res := &httpResult{HTTPResponse: resp, UploadedFiles: files}
	if s.includeRequest {
		var sum *bodySummary
		if s.body != nil {
			sum = s.body.summary
		}
		res.Request = echoRequest(req, sum)
	}
	return res, nil
}
