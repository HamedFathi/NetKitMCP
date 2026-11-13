package httptools

import (
	"context"
	"crypto/md5" //nolint:gosec // Content-MD5 is an integrity header, not a security hash
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const maxUploadRetries = 10

type uploadIn struct {
	URL               string            `json:"url" jsonschema:"target URL, e.g. a presigned S3/GCS/Azure Blob URL"`
	File              string            `json:"file" jsonschema:"file to upload (inside an allowed read directory); streamed, never loaded into memory"`
	Method            string            `json:"method,omitempty" jsonschema:"PUT (default) or POST"`
	ContentType       string            `json:"content_type,omitempty" jsonschema:"Content-Type (default detected from the extension or content); must match what a presigned URL was signed with"`
	Headers           map[string]string `json:"headers,omitempty" jsonschema:"extra headers, e.g. x-ms-blob-type: BlockBlob, x-amz-acl, Content-Disposition"`
	Query             map[string]any    `json:"query,omitempty" jsonschema:"query parameters appended to the URL"`
	Checksum          string            `json:"checksum,omitempty" jsonschema:"md5 or sha256: hash the file first and send it (Content-MD5 or x-amz-checksum-sha256 by default)"`
	ChecksumHeader    string            `json:"checksum_header,omitempty" jsonschema:"header name for the checksum (overrides the default)"`
	ChecksumEncoding  string            `json:"checksum_encoding,omitempty" jsonschema:"base64 (default) or hex"`
	Retries           int               `json:"retries,omitempty" jsonschema:"retry this many times on network errors, 408, 429 and 5xx (default 0, max 10); the file is re-read each attempt"`
	RetryDelaySeconds float64           `json:"retry_delay_seconds,omitempty" jsonschema:"initial retry delay, doubled each attempt (default 1)"`
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"authentication (not needed for presigned URLs)"`
}

func handleUpload(d *tools.Deps) tools.Handler[uploadIn] {
	return func(ctx context.Context, mreq *mcp.CallToolRequest, in uploadIn) (any, error) {
		start := time.Now()
		u, err := buildURL(in.URL, in.Query)
		if err != nil {
			return nil, err
		}
		method, err := normalizeMethod(in.Method, "PUT")
		if err != nil {
			return nil, err
		}
		if method != "PUT" && method != "POST" && method != "PATCH" {
			return nil, fmt.Errorf("http_upload method must be PUT or POST (got %s); use http_request for other methods", method)
		}
		if in.Retries < 0 || in.Retries > maxUploadRetries {
			return nil, fmt.Errorf("retries must be between 0 and %d", maxUploadRetries)
		}
		fb, err := newFileBody(d.Files, in.File, d.Cfg.UploadBytes(0))
		if err != nil {
			return nil, err
		}
		var warnings []string
		meta := map[string]any{}
		headers := map[string]string{}
		for k, v := range in.Headers {
			headers[k] = v
		}

		provider := presignedProvider(u)
		if provider != "" {
			meta["presigned"] = provider
			if in.Auth != nil && in.Auth.Kind() != "none" {
				warnings = append(warnings, "the URL looks presigned ("+provider+"); auth was applied anyway and may invalidate the signature")
			}
			if provider == "azure" && !hasHeader(headers, "x-ms-blob-type") && method == "PUT" {
				headers["x-ms-blob-type"] = "BlockBlob"
				warnings = append(warnings, "added x-ms-blob-type: BlockBlob (required by Azure Blob Put Blob)")
			}
		}

		contentType := fb.info.ContentType
		if in.ContentType != "" {
			contentType = in.ContentType
		}
		fb.info.ContentType = contentType

		// Optional checksum: a streaming first pass over the file.
		var precomputedSHA string
		if in.Checksum != "" {
			name, value, sha, err := checksumHeader(d, fb, in.Checksum, in.ChecksumHeader, in.ChecksumEncoding)
			if err != nil {
				return nil, err
			}
			headers[name] = value
			precomputedSHA = sha
			meta["checksum"] = map[string]string{"algorithm": strings.ToLower(in.Checksum), "header": name, "value": value}
		}

		c, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
		if err != nil {
			return nil, err
		}
		defer c.Close()

		rep := progress.FromRequest(mreq)
		fb.wrap = func(r io.Reader) io.Reader { return rep.Reader(ctx, r, fb.info.SizeBytes, "uploading "+fb.info.Name) }

		delay := time.Second
		if in.RetryDelaySeconds > 0 {
			delay = time.Duration(in.RetryDelaySeconds * float64(time.Second))
		}
		var resp *types.HTTPResponse
		var lastErr error
		attempts := 0
		for attempt := 0; attempt <= in.Retries; attempt++ {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(delay):
				}
				delay *= 2
			}
			attempts++
			resp, lastErr = uploadOnce(ctx, c, method, u, headers, contentType, fb)
			if lastErr != nil {
				if !retryableErr(ctx, lastErr) {
					break
				}
				warnings = append(warnings, fmt.Sprintf("attempt %d failed: %v", attempts, lastErr))
				continue
			}
			if retryableStatus(resp.Status) && attempt < in.Retries {
				warnings = append(warnings, fmt.Sprintf("attempt %d: HTTP %d, retrying", attempts, resp.Status))
				continue
			}
			break
		}
		meta["attempts"] = attempts
		if lastErr != nil {
			return nil, fmt.Errorf("upload failed after %d attempt(s): %w", attempts, lastErr)
		}

		sent, sum := fb.Sent()
		info := fb.Info()
		if info.SHA256 == "" {
			info.SHA256 = precomputedSHA
		}
		if precomputedSHA != "" && sum != "" && sent == info.SizeBytes && sum != precomputedSHA {
			warnings = append(warnings, "file content changed between the checksum pass and the upload")
		}
		out := &types.TransferResult{
			File:             info,
			BytesTransferred: sent,
			Parts:            1,
			Remote: types.RemoteInfo{
				Status:   resp.Status,
				Location: header(resp, "Location"),
				ETag:     header(resp, "Etag"),
			},
			Response: resp,
			Meta:     meta,
		}
		out.TimingMS.Total = types.MS(time.Since(start))
		if resp.Status >= 300 {
			warnings = append(warnings, fmt.Sprintf("the server answered HTTP %d; see response for details", resp.Status))
		}
		out.Warnings = append(warnings, resp.Warnings...)
		resp.Warnings = nil
		return out, nil
	}
}

// uploadOnce performs one upload attempt, re-opening the file.
func uploadOnce(ctx context.Context, c *httpx.Client, method string, u *url.URL, headers map[string]string, contentType string, fb *fileBody) (*types.HTTPResponse, error) {
	rctx, cancel := c.Context(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	applyHeaders(req, headers)
	if req.Header.Get("Content-Type") == "" && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if fb.info.SizeBytes == 0 {
		req.Body = http.NoBody
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	} else {
		rc, err := fb.Open()
		if err != nil {
			return nil, err
		}
		req.Body = rc
		req.ContentLength = fb.info.SizeBytes
		req.GetBody = fb.Open
	}
	return execute(c, req, httpx.ReadOptions{})
}

func header(r *types.HTTPResponse, name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func retryableStatus(s int) bool {
	return s == http.StatusRequestTimeout || s == http.StatusTooManyRequests || s >= 500
}

func retryableErr(ctx context.Context, err error) bool {
	return ctx.Err() == nil && !errors.Is(err, netguard.ErrBlocked) && !errors.Is(err, fileio.ErrDenied)
}

// checksumHeader hashes the file in a streaming pass and returns the header
// name and encoded value, plus the file's SHA-256 (hex).
func checksumHeader(d *tools.Deps, fb *fileBody, algo, name, encoding string) (string, string, string, error) {
	var h hash.Hash
	defName := ""
	switch strings.ToLower(strings.ReplaceAll(algo, "-", "")) {
	case "md5":
		h = md5.New() //nolint:gosec
		defName = "Content-MD5"
	case "sha256":
		h = sha256.New()
		defName = "x-amz-checksum-sha256"
	default:
		return "", "", "", fmt.Errorf("checksum must be md5 or sha256 (got %q)", algo)
	}
	if name == "" {
		name = defName
	}
	f, _, err := d.Files.OpenRead(fb.path, fb.max)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()
	sh := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h, sh), f); err != nil {
		return "", "", "", fmt.Errorf("hashing %s: %w", fb.info.Name, err)
	}
	sum := h.Sum(nil)
	var value string
	switch strings.ToLower(encoding) {
	case "", "base64":
		value = base64.StdEncoding.EncodeToString(sum)
	case "hex":
		value = hex.EncodeToString(sum)
	default:
		return "", "", "", fmt.Errorf("checksum_encoding must be base64 or hex")
	}
	return name, value, hex.EncodeToString(sh.Sum(nil)), nil
}

// presignedProvider recognises presigned/SAS URLs by their query parameters.
func presignedProvider(u *url.URL) string {
	q := u.Query()
	has := func(k string) bool {
		for key := range q {
			if strings.EqualFold(key, k) {
				return true
			}
		}
		return false
	}
	switch {
	case has("X-Amz-Signature") || (has("Signature") && has("AWSAccessKeyId")):
		return "s3"
	case has("X-Goog-Signature") || (has("Signature") && has("GoogleAccessId")):
		return "gcs"
	case has("sig") && (has("sv") || has("se")):
		return "azure"
	}
	return ""
}
