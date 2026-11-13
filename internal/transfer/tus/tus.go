// Package tus is a small tus 1.0 resumable-upload client (core protocol plus
// the creation, creation-with-upload and checksum extensions) built on a
// caller-supplied *http.Client, so the shared SSRF guard and auth apply.
package tus

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/transfer"
)

// Version is the protocol version this client speaks.
const Version = "1.0.0"

// DefaultChunkSize is the PATCH chunk size used when none is given.
const DefaultChunkSize = 8 << 20

// Options configure one upload.
type Options struct {
	Client    *http.Client
	UserAgent string
	// Endpoint is the creation URL (POST). Required unless UploadURL is set.
	Endpoint string
	// UploadURL resumes an upload created earlier.
	UploadURL string
	File      io.ReaderAt
	Size      int64
	Metadata  map[string]string
	Headers   http.Header
	ChunkSize int64
	// CreationWithUpload sends the first chunk in the creation POST when the
	// server supports the creation-with-upload extension.
	CreationWithUpload bool
	// Checksum sends Upload-Checksum (sha1) with each chunk when supported.
	Checksum       bool
	MaxRetries     int
	RetryDelay     time.Duration
	RequestTimeout time.Duration
	// Observe is called with every byte range read for sending (may repeat
	// ranges on retry).
	Observe  func(pos int64, b []byte)
	Progress func(done, total int64)
}

// ServerInfo is what OPTIONS discovery reported.
type ServerInfo struct {
	Version            string   `json:"tus_resumable,omitempty"`
	Versions           []string `json:"tus_versions,omitempty"`
	Extensions         []string `json:"extensions,omitempty"`
	MaxSize            int64    `json:"max_size,omitempty"`
	ChecksumAlgorithms []string `json:"checksum_algorithms,omitempty"`
	Discovered         bool     `json:"discovered"`
}

func (s ServerInfo) has(ext string) bool {
	for _, e := range s.Extensions {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}

// Result describes a finished upload.
type Result struct {
	UploadURL     string
	Offset        int64
	ResumedFrom   int64
	BytesSent     int64
	Requests      int
	Chunks        int
	Retries       int
	LastStatus    int
	Created       bool
	ChecksumsSent bool
	Server        ServerInfo
	Warnings      []string
}

// Error is returned when an upload fails after the upload resource exists;
// it carries what is needed to resume.
type Error struct {
	UploadURL string
	Offset    int64
	Size      int64
	Err       error
}

func (e *Error) Error() string {
	if e.UploadURL == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("tus upload stopped at offset %d of %d: %v. Resume by calling tus_upload again with upload_url=%q", e.Offset, e.Size, e.Err, e.UploadURL)
}

func (e *Error) Unwrap() error { return e.Err }

// StatusError is a non-retryable HTTP status.
type StatusError struct {
	Op     string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("%s: server answered %d %s", e.Op, e.Status, http.StatusText(e.Status))
	if b := strings.TrimSpace(e.Body); b != "" {
		msg += ": " + b
	}
	return msg
}

type uploader struct {
	o   Options
	res *Result
}

// Upload runs the upload to completion (or failure).
func Upload(ctx context.Context, o Options) (*Result, error) {
	if o.Client == nil {
		return nil, errors.New("tus: no HTTP client")
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = DefaultChunkSize
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 30 * time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	u := &uploader{o: o, res: &Result{}}
	return u.run(ctx)
}

func (u *uploader) run(ctx context.Context) (*Result, error) {
	o := u.o
	target := o.UploadURL
	if target == "" {
		target = o.Endpoint
	}
	if target == "" {
		return nil, errors.New("tus: url (creation endpoint) or upload_url is required")
	}
	u.discover(ctx, target)
	srv := u.res.Server
	if srv.Discovered && srv.MaxSize > 0 && o.Size > srv.MaxSize {
		return nil, fmt.Errorf("file is %d bytes but the server's Tus-Max-Size is %d", o.Size, srv.MaxSize)
	}
	useChecksum := false
	if o.Checksum {
		switch {
		case !srv.Discovered:
			useChecksum = true
			u.warn("OPTIONS discovery failed; sending Upload-Checksum without confirming checksum support")
		case !srv.has("checksum"):
			u.warn("server does not advertise the checksum extension; chunks sent without Upload-Checksum")
		case !containsFold(srv.ChecksumAlgorithms, "sha1"):
			u.warn("server does not support sha1 checksums; chunks sent without Upload-Checksum")
		default:
			useChecksum = true
		}
	}
	u.res.ChecksumsSent = useChecksum

	var offset int64
	if o.UploadURL != "" {
		u.res.UploadURL = o.UploadURL
		off, length, err := u.head(ctx)
		if err != nil {
			return nil, err
		}
		if length >= 0 && length != o.Size {
			return nil, fmt.Errorf("upload_url has Upload-Length %d but the file is %d bytes; it belongs to a different file (omit upload_url to start a new upload)", length, o.Size)
		}
		if off > o.Size {
			return nil, fmt.Errorf("server reports Upload-Offset %d beyond the file size %d", off, o.Size)
		}
		offset = off
		u.res.ResumedFrom = off
	} else {
		if srv.Discovered && !srv.has("creation") {
			return nil, errors.New("server does not support the tus creation extension; create the upload out of band and pass upload_url")
		}
		withUpload := o.CreationWithUpload
		if withUpload && srv.Discovered && !srv.has("creation-with-upload") {
			withUpload = false
			u.warn("server does not advertise creation-with-upload; creating first, then uploading")
		}
		off, err := u.create(ctx, withUpload, useChecksum)
		if err != nil {
			return nil, u.wrap(err, off)
		}
		offset = off
	}

	start := offset
	attempt := 0
	for offset < o.Size {
		n := o.Size - offset
		if n > o.ChunkSize {
			n = o.ChunkSize
		}
		newOff, err := u.patch(ctx, offset, n, useChecksum)
		if err == nil {
			offset = newOff
			attempt = 0
			continue
		}
		var se *StatusError
		if errors.As(err, &se) && !retryableStatus(se.Status) {
			return nil, u.wrap(err, offset)
		}
		if ctx.Err() != nil {
			return nil, u.wrap(ctx.Err(), offset)
		}
		attempt++
		if attempt > o.MaxRetries {
			// Best effort: learn how much the server kept.
			if off, _, herr := u.head(ctx); herr == nil {
				offset = off
			}
			return nil, u.wrap(err, offset)
		}
		u.res.Retries++
		if berr := transfer.Backoff(ctx, o.RetryDelay, attempt); berr != nil {
			return nil, u.wrap(berr, offset)
		}
		off, _, herr := u.head(ctx)
		if herr != nil {
			var hse *StatusError
			if errors.As(herr, &hse) {
				return nil, u.wrap(herr, offset)
			}
			continue // network still failing; counts against the next attempt
		}
		offset = off
	}
	u.res.Offset = offset
	u.res.BytesSent = offset - start
	if u.res.Created {
		u.res.BytesSent = offset
	}
	return u.res, nil
}

func (u *uploader) wrap(err error, offset int64) error {
	return &Error{UploadURL: u.res.UploadURL, Offset: offset, Size: u.o.Size, Err: err}
}

func (u *uploader) warn(s string) { u.res.Warnings = append(u.res.Warnings, s) }

func retryableStatus(code int) bool {
	switch code {
	case http.StatusConflict, http.StatusLocked, http.StatusRequestTimeout, http.StatusTooManyRequests, 460:
		return true
	}
	return code >= 500
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (u *uploader) newRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range u.o.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Tus-Resumable", Version)
	if u.o.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", u.o.UserAgent)
	}
	return req, nil
}

func (u *uploader) do(req *http.Request) (*http.Response, error) {
	u.res.Requests++
	resp, err := u.o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	u.res.LastStatus = resp.StatusCode
	return resp, nil
}

func readSmall(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 2048))
	return string(b)
}

func (u *uploader) discover(ctx context.Context, target string) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	req, err := u.newRequest(ctx, http.MethodOptions, target, nil)
	if err != nil {
		return
	}
	resp, err := u.do(req)
	if err != nil {
		u.warn("OPTIONS discovery failed: " + err.Error())
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		u.warn(fmt.Sprintf("OPTIONS discovery answered %d; continuing without capability information", resp.StatusCode))
		return
	}
	s := &u.res.Server
	s.Discovered = resp.Header.Get("Tus-Version") != "" || resp.Header.Get("Tus-Extension") != ""
	if !s.Discovered {
		u.warn("OPTIONS response carried no Tus-Version header; is this a tus endpoint?")
		return
	}
	s.Version = resp.Header.Get("Tus-Resumable")
	s.Versions = splitList(resp.Header.Get("Tus-Version"))
	s.Extensions = splitList(resp.Header.Get("Tus-Extension"))
	s.ChecksumAlgorithms = splitList(resp.Header.Get("Tus-Checksum-Algorithm"))
	if v := resp.Header.Get("Tus-Max-Size"); v != "" {
		s.MaxSize, _ = strconv.ParseInt(v, 10, 64)
	}
	if len(s.Versions) > 0 && !containsFold(s.Versions, Version) {
		u.warn("server does not list tus version " + Version + " in Tus-Version: " + strings.Join(s.Versions, ","))
	}
}

// EncodeMetadata builds an Upload-Metadata header value (keys sorted).
func EncodeMetadata(md map[string]string) string {
	keys := make([]string, 0, len(md))
	for k := range md {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if md[k] == "" {
			parts = append(parts, k)
			continue
		}
		parts = append(parts, k+" "+base64.StdEncoding.EncodeToString([]byte(md[k])))
	}
	return strings.Join(parts, ",")
}

// ValidMetadataKey reports whether k is usable as an Upload-Metadata key.
func ValidMetadataKey(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if r <= ' ' || r == ',' || r > '~' {
			return false
		}
	}
	return true
}

func (u *uploader) chunkBody(offset, n int64) io.Reader {
	var r io.Reader = io.NewSectionReader(u.o.File, offset, n)
	total := u.o.Size
	prog := u.o.Progress
	obs := u.o.Observe
	return &transfer.ObservedReader{R: r, Pos: offset, Observe: func(pos int64, b []byte) {
		if obs != nil {
			obs(pos, b)
		}
		if prog != nil {
			prog(pos+int64(len(b)), total)
		}
	}}
}

func (u *uploader) sha1Of(offset, n int64) (string, error) {
	h := sha1.New()
	if _, err := io.Copy(h, io.NewSectionReader(u.o.File, offset, n)); err != nil {
		return "", err
	}
	return "sha1 " + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// create POSTs the upload; with withUpload it also sends the first chunk.
// It returns the server offset after creation.
func (u *uploader) create(ctx context.Context, withUpload, checksum bool) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	var body io.Reader
	var n int64
	if withUpload && u.o.Size > 0 {
		n = u.o.Size
		if n > u.o.ChunkSize {
			n = u.o.ChunkSize
		}
		body = u.chunkBody(0, n)
	}
	req, err := u.newRequest(ctx, http.MethodPost, u.o.Endpoint, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Upload-Length", strconv.FormatInt(u.o.Size, 10))
	if md := EncodeMetadata(u.o.Metadata); md != "" {
		req.Header.Set("Upload-Metadata", md)
	}
	if body != nil {
		req.ContentLength = n
		req.Header.Set("Content-Type", "application/offset+octet-stream")
		if checksum {
			sum, err := u.sha1Of(0, n)
			if err != nil {
				return 0, err
			}
			req.Header.Set("Upload-Checksum", sum)
		}
	} else {
		req.ContentLength = 0
	}
	resp, err := u.do(req)
	if err != nil {
		return 0, fmt.Errorf("creation request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode/100 != 2 {
		return 0, &StatusError{Op: "creation (POST)", Status: resp.StatusCode, Body: readSmall(resp.Body)}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	loc := resp.Header.Get("Location")
	if loc == "" {
		return 0, errors.New("creation response has no Location header")
	}
	abs, err := resolve(resp.Request.URL, loc)
	if err != nil {
		return 0, fmt.Errorf("creation Location %q: %w", loc, err)
	}
	u.res.UploadURL = abs
	u.res.Created = true
	if body != nil {
		u.res.Chunks++
		if v := resp.Header.Get("Upload-Offset"); v != "" {
			off, err := strconv.ParseInt(v, 10, 64)
			if err == nil && off >= 0 && off <= u.o.Size {
				return off, nil
			}
		}
		// Server did not confirm the offset; ask.
		off, _, err := u.head(context.WithoutCancel(ctx))
		if err != nil {
			return 0, err
		}
		return off, nil
	}
	return 0, nil
}

func resolve(base *url.URL, ref string) (string, error) {
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(r).String(), nil
}

// head returns the server's Upload-Offset and Upload-Length (-1 if absent).
func (u *uploader) head(ctx context.Context) (int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	req, err := u.newRequest(ctx, http.MethodHead, u.res.UploadURL, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := u.do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("HEAD %s: %w", u.res.UploadURL, err)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return 0, 0, &StatusError{Op: "HEAD (resume)", Status: resp.StatusCode, Body: "the upload no longer exists on the server; omit upload_url to start a new upload"}
	case resp.StatusCode/100 != 2:
		return 0, 0, &StatusError{Op: "HEAD (resume)", Status: resp.StatusCode}
	}
	off, err := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || off < 0 {
		return 0, 0, fmt.Errorf("HEAD response has an invalid Upload-Offset %q", resp.Header.Get("Upload-Offset"))
	}
	length := int64(-1)
	if v := resp.Header.Get("Upload-Length"); v != "" {
		if l, err := strconv.ParseInt(v, 10, 64); err == nil {
			length = l
		}
	}
	return off, length, nil
}

func (u *uploader) patch(ctx context.Context, offset, n int64, checksum bool) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	req, err := u.newRequest(ctx, http.MethodPatch, u.res.UploadURL, u.chunkBody(offset, n))
	if err != nil {
		return 0, err
	}
	req.ContentLength = n
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	if checksum {
		sum, err := u.sha1Of(offset, n)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Upload-Checksum", sum)
	}
	resp, err := u.do(req)
	if err != nil {
		return 0, fmt.Errorf("PATCH at offset %d: %w", offset, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, &StatusError{Op: fmt.Sprintf("PATCH at offset %d", offset), Status: resp.StatusCode, Body: readSmall(resp.Body)}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	u.res.Chunks++
	newOff, err := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || newOff < offset || newOff > u.o.Size {
		return 0, fmt.Errorf("PATCH response has an invalid Upload-Offset %q", resp.Header.Get("Upload-Offset"))
	}
	return newOff, nil
}
