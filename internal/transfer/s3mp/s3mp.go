// Package s3mp implements S3-compatible multipart uploads (create, upload
// part, complete, abort, list parts) signed with AWS Signature Version 4.
// Parts are streamed from disk: each part is hashed in a first pass (for the
// signed payload hash) and streamed in a second, so memory use is constant.
package s3mp

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/HamedFathi/NetKitMCP/internal/transfer"
)

// Part size bounds imposed by S3.
const (
	MinPartSize     = 5 << 20
	MaxPartSize     = 5 << 30
	DefaultPartSize = 8 << 20
	MaxParts        = 10000
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Options configure one multipart upload.
type Options struct {
	Client    *http.Client
	UserAgent string
	// Endpoint is the service base URL, e.g. https://s3.eu-west-1.amazonaws.com
	// or http://minio:9000.
	Endpoint     string
	Region       string
	Bucket       string
	Key          string
	PathStyle    bool
	Credentials  aws.Credentials
	File         io.ReaderAt
	Size         int64
	PartSize     int64
	ContentType  string
	Metadata     map[string]string
	StorageClass string
	Headers      http.Header
	// ResumeUploadID continues an existing multipart upload: parts already
	// listed by the server with a matching size (and MD5 ETag) are skipped.
	ResumeUploadID string
	KeepOnFailure  bool
	MaxRetries     int
	RetryDelay     time.Duration
	RequestTimeout time.Duration
	Observe        func(pos int64, b []byte)
	Progress       func(done, total int64)
}

// Result describes a completed upload.
type Result struct {
	UploadID      string
	Location      string
	ETag          string
	Status        int
	Parts         int
	PartsUploaded int
	PartsSkipped  int
	PartSize      int64
	BytesSent     int64
	ResumedFrom   int64
	Retries       int
	Warnings      []string
	ObjectURL     string
}

// Error is returned on failure; UploadID is set when the upload was kept
// on the server for a later resume.
type Error struct {
	UploadID string
	Kept     bool
	Aborted  bool
	Err      error
}

func (e *Error) Error() string {
	switch {
	case e.Kept:
		return fmt.Sprintf("%v. The multipart upload was kept; resume with resume_upload_id=%q", e.Err, e.UploadID)
	case e.Aborted:
		return fmt.Sprintf("%v. The multipart upload %s was aborted (set keep_on_failure=true to keep it for a resume)", e.Err, e.UploadID)
	case e.UploadID != "":
		return fmt.Sprintf("%v (upload id %s)", e.Err, e.UploadID)
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// APIError is an S3 error response.
type APIError struct {
	Op        string
	Status    int
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	RequestID string `xml:"RequestId"`
	raw       string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s: S3 answered %d", e.Op, e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	} else if e.raw != "" && e.Code == "" {
		msg += ": " + e.raw
	}
	if e.Code == "SignatureDoesNotMatch" || e.Code == "InvalidAccessKeyId" {
		msg += " (check access_key_id/secret_access_key and region)"
	}
	return msg
}

func retryable(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests || ae.Status == http.StatusRequestTimeout ||
			ae.Code == "RequestTimeout" || ae.Code == "SlowDown" || ae.Code == "InternalError"
	}
	return !errors.Is(err, context.Canceled)
}

type uploader struct {
	o      Options
	signer *v4.Signer
	res    *Result
	base   *url.URL
}

// ChoosePartSize returns a part size >= requested that keeps the number of
// parts within MaxParts.
func ChoosePartSize(size, requested int64) int64 {
	ps := requested
	if ps <= 0 {
		ps = DefaultPartSize
	}
	if ps < MinPartSize {
		ps = MinPartSize
	}
	for size > ps*MaxParts && ps < MaxPartSize {
		ps *= 2
	}
	if ps > MaxPartSize {
		ps = MaxPartSize
	}
	return ps
}

// Upload runs the multipart upload.
func Upload(ctx context.Context, o Options) (*Result, error) {
	if o.Client == nil {
		return nil, errors.New("s3: no HTTP client")
	}
	if o.Bucket == "" || o.Key == "" {
		return nil, errors.New("bucket and key are required")
	}
	if o.Credentials.AccessKeyID == "" || o.Credentials.SecretAccessKey == "" {
		return nil, errors.New("AWS credentials are required: set aws.access_key_id and aws.secret_access_key (or auth.type=aws_sigv4 with auth.aws)")
	}
	if o.Region == "" {
		o.Region = "us-east-1"
	}
	if o.Endpoint == "" {
		o.Endpoint = "https://s3." + o.Region + ".amazonaws.com"
	}
	base, err := url.Parse(strings.TrimRight(o.Endpoint, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("invalid endpoint %q (want http(s)://host[:port])", o.Endpoint)
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 30 * time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	requested := o.PartSize
	o.PartSize = ChoosePartSize(o.Size, o.PartSize)
	u := &uploader{
		o:      o,
		base:   base,
		res:    &Result{PartSize: o.PartSize},
		signer: v4.NewSigner(func(so *v4.SignerOptions) { so.DisableURIPathEscaping = true }),
	}
	if requested > 0 && requested != o.PartSize {
		u.warn(fmt.Sprintf("part_size adjusted from %d to %d bytes (S3 requires 5 MiB..5 GiB and at most %d parts)", requested, o.PartSize, MaxParts))
	}
	u.res.ObjectURL = u.objectURL(nil).String()
	return u.run(ctx)
}

func (u *uploader) warn(s string) { u.res.Warnings = append(u.res.Warnings, s) }

// escapeKey percent-encodes an object key the way S3 canonicalizes it.
func escapeKey(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (u *uploader) objectURL(q url.Values) *url.URL {
	out := *u.base
	key := strings.TrimPrefix(u.o.Key, "/")
	basePath := strings.TrimRight(u.base.Path, "/")
	var p string
	if u.o.PathStyle {
		p = basePath + "/" + u.o.Bucket + "/" + key
	} else {
		out.Host = u.o.Bucket + "." + u.base.Host
		p = basePath + "/" + key
	}
	out.Path = p
	out.RawPath = escapeKey(p)
	if q != nil {
		out.RawQuery = encodeQuery(q)
	} else {
		out.RawQuery = ""
	}
	return &out
}

func encodeQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			if v == "" {
				parts = append(parts, url.QueryEscape(k))
			} else {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
	}
	return strings.Join(parts, "&")
}

// send signs and sends one request. body may be nil; payloadHash is the hex
// SHA-256 of the body.
func (u *uploader) send(ctx context.Context, op, method string, q url.Values, hdr http.Header, body io.Reader, length int64, payloadHash string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.objectURL(q).String(), body)
	if err != nil {
		return nil, err
	}
	req.URL = u.objectURL(q)
	req.ContentLength = length
	if length == 0 {
		req.Body = http.NoBody
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if u.o.UserAgent != "" {
		req.Header.Set("User-Agent", u.o.UserAgent)
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := u.signer.SignHTTP(ctx, u.o.Credentials, req, payloadHash, "s3", u.o.Region, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("%s: signing: %w", op, err)
	}
	resp, err := u.o.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	u.res.Status = resp.StatusCode
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, parseAPIError(op, resp)
	}
	return resp, nil
}

func parseAPIError(op string, resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	ae := &APIError{Op: op, Status: resp.StatusCode}
	if len(bytes.TrimSpace(data)) > 0 {
		if xml.Unmarshal(data, ae) != nil || ae.Code == "" {
			s := strings.TrimSpace(string(data))
			if len(s) > 300 {
				s = s[:300] + "..."
			}
			ae.raw = s
		}
	}
	return ae
}

// readXML decodes a 2xx XML body, detecting the S3 "200 with <Error>" case.
func readXML(op string, resp *http.Response, v any) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("%s: reading response: %w", op, err)
	}
	if bytes.Contains(data, []byte("<Error>")) {
		ae := &APIError{Op: op, Status: resp.StatusCode}
		if xml.Unmarshal(data, ae) == nil && ae.Code != "" {
			return ae
		}
	}
	if v == nil {
		return nil
	}
	if err := xml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: invalid XML response: %w", op, err)
	}
	return nil
}

type initiateResult struct {
	Bucket   string `xml:"Bucket"`
	Key      string `xml:"Key"`
	UploadID string `xml:"UploadId"`
}

type listPartsResult struct {
	IsTruncated          bool   `xml:"IsTruncated"`
	NextPartNumberMarker int    `xml:"NextPartNumberMarker"`
	Parts                []part `xml:"Part"`
}

type part struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size,omitempty"`
}

type completeRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []part   `xml:"Part"`
}

type completeResult struct {
	Location string `xml:"Location"`
	Bucket   string `xml:"Bucket"`
	Key      string `xml:"Key"`
	ETag     string `xml:"ETag"`
}

func (u *uploader) run(ctx context.Context) (*Result, error) {
	o := u.o
	uploadID := o.ResumeUploadID
	existing := map[int]part{}
	if uploadID != "" {
		ps, err := u.listParts(ctx, uploadID)
		if err != nil {
			return nil, &Error{UploadID: uploadID, Err: err}
		}
		for _, p := range ps {
			existing[p.PartNumber] = p
		}
		if p1, ok := existing[1]; ok && p1.Size > 0 && p1.Size != o.PartSize && p1.Size < o.Size {
			if p1.Size < MinPartSize {
				return nil, &Error{UploadID: uploadID, Err: fmt.Errorf("existing part 1 is %d bytes, below the S3 minimum; cannot resume", p1.Size)}
			}
			u.warn(fmt.Sprintf("using part size %d from the existing upload (requested %d)", p1.Size, o.PartSize))
			u.o.PartSize = p1.Size
			u.res.PartSize = p1.Size
		}
	} else {
		id, err := u.create(ctx)
		if err != nil {
			return nil, &Error{Err: err}
		}
		uploadID = id
	}
	u.res.UploadID = uploadID

	fail := func(err error) (*Result, error) {
		e := &Error{UploadID: uploadID, Err: err}
		if u.o.KeepOnFailure {
			e.Kept = true
			return nil, e
		}
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), u.o.RequestTimeout)
		defer cancel()
		if aerr := u.abort(actx, uploadID); aerr != nil {
			e.Err = fmt.Errorf("%w (abort also failed: %v)", err, aerr)
			return nil, e
		}
		e.Aborted = true
		return nil, e
	}

	ps := u.o.PartSize
	nParts := int((o.Size + ps - 1) / ps)
	if nParts == 0 {
		nParts = 1 // zero-byte object: one empty part
	}
	var done []part
	var resumedContiguous = true
	for i := 1; i <= nParts; i++ {
		off := int64(i-1) * ps
		n := ps
		if off+n > o.Size {
			n = o.Size - off
		}
		if p, ok := existing[i]; ok && p.Size == n {
			match, err := u.etagMatches(off, n, p.ETag)
			if err != nil {
				return fail(err)
			}
			if match {
				done = append(done, part{PartNumber: i, ETag: p.ETag})
				u.res.PartsSkipped++
				if resumedContiguous {
					u.res.ResumedFrom = off + n
				}
				if o.Progress != nil {
					o.Progress(off+n, o.Size)
				}
				continue
			}
			u.warn(fmt.Sprintf("existing part %d does not match the local file; re-uploading it", i))
		}
		resumedContiguous = false
		etag, err := u.uploadPartRetry(ctx, uploadID, i, off, n)
		if err != nil {
			return fail(err)
		}
		done = append(done, part{PartNumber: i, ETag: etag})
		u.res.PartsUploaded++
		u.res.BytesSent += n
	}
	u.res.Parts = len(done)
	if err := u.complete(ctx, uploadID, done); err != nil {
		return fail(err)
	}
	return u.res, nil
}

// etagMatches compares a plain-MD5 ETag with the local part; non-MD5 ETags
// (SSE-KMS, other stores) are trusted when the size matches.
func (u *uploader) etagMatches(off, n int64, etag string) (bool, error) {
	e := strings.Trim(etag, `"`)
	if len(e) != 32 {
		return true, nil
	}
	if _, err := hex.DecodeString(e); err != nil {
		return true, nil
	}
	h := md5.New()
	if _, err := io.Copy(h, io.NewSectionReader(u.o.File, off, n)); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), e), nil
}

func (u *uploader) create(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	hdr := http.Header{}
	for k, vs := range u.o.Headers {
		hdr[http.CanonicalHeaderKey(k)] = vs
	}
	if u.o.ContentType != "" {
		hdr.Set("Content-Type", u.o.ContentType)
	}
	for k, v := range u.o.Metadata {
		hdr.Set("X-Amz-Meta-"+k, v)
	}
	if u.o.StorageClass != "" {
		hdr.Set("X-Amz-Storage-Class", u.o.StorageClass)
	}
	resp, err := u.send(ctx, "CreateMultipartUpload", http.MethodPost, url.Values{"uploads": {""}}, hdr, nil, 0, emptySHA256)
	if err != nil {
		return "", err
	}
	var ir initiateResult
	if err := readXML("CreateMultipartUpload", resp, &ir); err != nil {
		return "", err
	}
	if ir.UploadID == "" {
		return "", errors.New("CreateMultipartUpload: response has no UploadId")
	}
	return ir.UploadID, nil
}

func (u *uploader) listParts(ctx context.Context, uploadID string) ([]part, error) {
	var out []part
	marker := 0
	for page := 0; page < 20; page++ {
		rctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
		q := url.Values{"uploadId": {uploadID}}
		if marker > 0 {
			q.Set("part-number-marker", strconv.Itoa(marker))
		}
		resp, err := u.send(rctx, "ListParts", http.MethodGet, q, nil, nil, 0, emptySHA256)
		if err != nil {
			cancel()
			return nil, err
		}
		var lr listPartsResult
		err = readXML("ListParts", resp, &lr)
		cancel()
		if err != nil {
			return nil, err
		}
		out = append(out, lr.Parts...)
		if !lr.IsTruncated || lr.NextPartNumberMarker <= marker {
			break
		}
		marker = lr.NextPartNumberMarker
	}
	return out, nil
}

func (u *uploader) uploadPartRetry(ctx context.Context, uploadID string, num int, off, n int64) (string, error) {
	// First pass: payload hash (required for the signature).
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(u.o.File, off, n)); err != nil {
		return "", fmt.Errorf("reading part %d: %w", num, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	var lastErr error
	for attempt := 0; attempt <= u.o.MaxRetries; attempt++ {
		if attempt > 0 {
			u.res.Retries++
			if err := transfer.Backoff(ctx, u.o.RetryDelay, attempt); err != nil {
				return "", err
			}
		}
		etag, err := u.uploadPart(ctx, uploadID, num, off, n, sum)
		if err == nil {
			return etag, nil
		}
		lastErr = err
		if ctx.Err() != nil || !retryable(err) {
			break
		}
	}
	return "", lastErr
}

func (u *uploader) uploadPart(ctx context.Context, uploadID string, num int, off, n int64, sum string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	total := u.o.Size
	obs, prog := u.o.Observe, u.o.Progress
	body := &transfer.ObservedReader{R: io.NewSectionReader(u.o.File, off, n), Pos: off, Observe: func(pos int64, b []byte) {
		if obs != nil {
			obs(pos, b)
		}
		if prog != nil {
			prog(pos+int64(len(b)), total)
		}
	}}
	var rd io.Reader = body
	if n == 0 {
		rd = nil
	}
	op := fmt.Sprintf("UploadPart %d", num)
	q := url.Values{"partNumber": {strconv.Itoa(num)}, "uploadId": {uploadID}}
	resp, err := u.send(ctx, op, http.MethodPut, q, nil, rd, n, sum)
	if err != nil {
		return "", err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", fmt.Errorf("%s: response has no ETag", op)
	}
	return etag, nil
}

func (u *uploader) complete(ctx context.Context, uploadID string, parts []part) error {
	ctx, cancel := context.WithTimeout(ctx, u.o.RequestTimeout)
	defer cancel()
	body, err := xml.Marshal(completeRequest{Parts: parts})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	hdr := http.Header{"Content-Type": {"application/xml"}}
	resp, err := u.send(ctx, "CompleteMultipartUpload", http.MethodPost, url.Values{"uploadId": {uploadID}}, hdr,
		bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	var cr completeResult
	if err := readXML("CompleteMultipartUpload", resp, &cr); err != nil {
		return err
	}
	u.res.Location = cr.Location
	u.res.ETag = cr.ETag
	if u.res.ETag == "" {
		u.res.ETag = resp.Header.Get("ETag")
	}
	return nil
}

func (u *uploader) abort(ctx context.Context, uploadID string) error {
	resp, err := u.send(ctx, "AbortMultipartUpload", http.MethodDelete, url.Values{"uploadId": {uploadID}}, nil, nil, 0, emptySHA256)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
