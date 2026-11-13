package transfertools_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// fakeS3 implements the multipart subset of the S3 API (path-style).
type fakeS3 struct {
	*httptest.Server
	t        *testing.T
	mu       sync.Mutex
	nextID   int
	uploads  map[string]map[int][]byte // uploadId -> part -> data
	headers  map[string]http.Header    // uploadId -> create headers
	objects  map[string][]byte
	aborted  []string
	partPuts []int
	// failPart makes UploadPart for that part number fail with 500 failCount times.
	failPart  int
	failCount int
	authErrs  []string
}

func newFakeS3(t *testing.T) *fakeS3 {
	f := &fakeS3{t: t, uploads: map[string]map[int][]byte{}, headers: map[string]http.Header{}, objects: map[string][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

var authRe = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDTEST/\d{8}/([a-z0-9-]+)/s3/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$`)

func (f *fakeS3) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>fake failure</Message></Error>`, code)
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m := authRe.FindStringSubmatch(r.Header.Get("Authorization"))
	f.mu.Lock()
	defer f.mu.Unlock()
	if m == nil || !strings.Contains(m[2], "host") || !strings.Contains(m[2], "x-amz-content-sha256") || !strings.Contains(m[2], "x-amz-date") {
		f.authErrs = append(f.authErrs, r.Header.Get("Authorization"))
		f.fail(w, 403, "AccessDenied")
		return
	}
	if err := verifySigV4(r, len(body), m[1]); err != nil {
		f.authErrs = append(f.authErrs, err.Error())
		f.fail(w, 403, "SignatureDoesNotMatch")
		return
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		f.authErrs = append(f.authErrs, "payload hash mismatch")
		f.fail(w, 400, "XAmzContentSHA256Mismatch")
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) != 2 || parts[0] != "bucket" {
		f.fail(w, 404, "NoSuchBucket")
		return
	}
	key := parts[1]
	q := r.URL.Query()
	uid := q.Get("uploadId")
	switch {
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.nextID++
		id := fmt.Sprintf("upload-%d", f.nextID)
		f.uploads[id] = map[int][]byte{}
		f.headers[id] = r.Header.Clone()
		fmt.Fprintf(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, key, id)
	case r.Method == http.MethodPut && uid != "":
		up, ok := f.uploads[uid]
		if !ok {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		n, _ := strconv.Atoi(q.Get("partNumber"))
		f.partPuts = append(f.partPuts, n)
		if n == f.failPart && f.failCount > 0 {
			f.failCount--
			f.fail(w, 500, "InternalError")
			return
		}
		up[n] = body
		md := md5.Sum(body)
		w.Header().Set("ETag", `"`+hex.EncodeToString(md[:])+`"`)
	case r.Method == http.MethodGet && uid != "":
		up, ok := f.uploads[uid]
		if !ok {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		var nums []int
		for n := range up {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var b strings.Builder
		b.WriteString("<ListPartsResult><IsTruncated>false</IsTruncated>")
		for _, n := range nums {
			md := md5.Sum(up[n])
			fmt.Fprintf(&b, `<Part><PartNumber>%d</PartNumber><ETag>"%x"</ETag><Size>%d</Size></Part>`, n, md, len(up[n]))
		}
		b.WriteString("</ListPartsResult>")
		io.WriteString(w, b.String())
	case r.Method == http.MethodPost && uid != "":
		up, ok := f.uploads[uid]
		if !ok {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		var req struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		if err := xml.Unmarshal(body, &req); err != nil {
			f.fail(w, 400, "MalformedXML")
			return
		}
		var obj bytes.Buffer
		for i, p := range req.Parts {
			data, ok := up[p.PartNumber]
			md := md5.Sum(data)
			if !ok || p.PartNumber != i+1 || strings.Trim(p.ETag, `"`) != hex.EncodeToString(md[:]) {
				f.fail(w, 400, "InvalidPart")
				return
			}
			obj.Write(data)
		}
		f.objects[key] = obj.Bytes()
		delete(f.uploads, uid)
		fmt.Fprintf(w, `<CompleteMultipartUploadResult><Location>%s/bucket/%s</Location><Bucket>bucket</Bucket><Key>%s</Key><ETag>"final-%d"</ETag></CompleteMultipartUploadResult>`, f.URL, key, key, len(req.Parts))
	case r.Method == http.MethodDelete && uid != "":
		delete(f.uploads, uid)
		f.aborted = append(f.aborted, uid)
		w.WriteHeader(204)
	default:
		f.fail(w, 400, "NotImplemented")
	}
}

// verifySigV4 re-signs the received request with the expected secret and
// compares the Authorization header.
func verifySigV4(r *http.Request, bodyLen int, region string) error {
	ts, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return fmt.Errorf("bad X-Amz-Date: %v", err)
	}
	u := *r.URL
	u.Scheme, u.Host = "http", r.Host
	req, _ := http.NewRequest(r.Method, u.String(), nil)
	req.URL = &u
	req.ContentLength = int64(bodyLen)
	signed := regexp.MustCompile(`SignedHeaders=([^,]+)`).FindStringSubmatch(r.Header.Get("Authorization"))[1]
	for _, hname := range strings.Split(signed, ";") {
		if hname == "host" || hname == "content-length" {
			continue
		}
		req.Header[http.CanonicalHeaderKey(hname)] = r.Header.Values(hname)
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret"}
	if err := signer.SignHTTP(context.Background(), creds, req, r.Header.Get("X-Amz-Content-Sha256"), "s3", region, ts); err != nil {
		return err
	}
	if got, want := r.Header.Get("Authorization"), req.Header.Get("Authorization"); got != want {
		return fmt.Errorf("signature mismatch: got %s want %s", got, want)
	}
	return nil
}

func s3Args(f *fakeS3, file string, extra map[string]any) map[string]any {
	a := map[string]any{
		"endpoint": f.URL, "bucket": "bucket", "key": "dir/my file+1.bin", "file": file, "region": "eu-west-1",
		"part_size": 5 << 20,
		"aws":       map[string]any{"access_key_id": "AKIDTEST", "secret_access_key": "secret"},
	}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestS3MultipartUpload(t *testing.T) {
	f := newFakeS3(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 11<<20+333)
	file := h.WriteInput("data.csv", data)
	r := h.MustOK("s3_multipart_upload", s3Args(f, file, map[string]any{
		"metadata": map[string]string{"owner": "tests"}, "storage_class": "STANDARD_IA",
	}))
	var out transferOut
	r.Decode(t, &out)
	if len(f.authErrs) > 0 {
		t.Fatalf("auth errors: %v", f.authErrs)
	}
	if got := f.objects["dir/my file+1.bin"]; !bytes.Equal(got, data) {
		t.Fatalf("object differs: %d bytes, keys %v", len(got), len(f.objects))
	}
	if out.Parts != 3 || out.BytesTransferred != int64(len(data)) || out.File.SHA256 != sha(data) {
		t.Fatalf("result: parts=%d bytes=%d sha=%s", out.Parts, out.BytesTransferred, out.File.SHA256)
	}
	if out.Remote.ETag != `"final-3"` || out.Remote.Status != 200 || out.Remote.Path != "bucket/dir/my file+1.bin" || out.Remote.Location == "" {
		t.Fatalf("remote: %+v", out.Remote)
	}
	hdr := f.headers["upload-1"]
	if out.File.ContentType == "" || hdr.Get("Content-Type") != out.File.ContentType {
		t.Fatalf("content type %q vs header %q", out.File.ContentType, hdr.Get("Content-Type"))
	}
	if hdr.Get("X-Amz-Meta-Owner") != "tests" || hdr.Get("X-Amz-Storage-Class") != "STANDARD_IA" {
		t.Fatalf("create headers: %v", hdr)
	}
}

func TestS3AuthSigV4AndRetry(t *testing.T) {
	f := newFakeS3(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 6<<20)
	file := h.WriteInput("a.bin", data)
	f.failPart, f.failCount = 2, 1
	args := s3Args(f, file, map[string]any{"max_retries": 2})
	delete(args, "aws")
	delete(args, "region")
	args["auth"] = map[string]any{"type": "aws_sigv4", "aws": map[string]any{
		"access_key_id": "AKIDTEST", "secret_access_key": "secret", "region": "us-west-2", "service": "s3"}}
	r := h.MustOK("s3_multipart_upload", args)
	var out transferOut
	r.Decode(t, &out)
	if out.Meta["retries"].(float64) != 1 || out.Meta["region"] != "us-west-2" {
		t.Fatalf("meta: %v", out.Meta)
	}
	if !bytes.Equal(f.objects["dir/my file+1.bin"], data) {
		t.Fatal("object differs")
	}
}

func TestS3AbortAndResume(t *testing.T) {
	f := newFakeS3(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 12<<20)
	file := h.WriteInput("a.bin", data)

	// Failure without keep_on_failure aborts.
	f.failPart, f.failCount = 2, 1
	h.MustFail("s3_multipart_upload", s3Args(f, file, map[string]any{"max_retries": 0}), "aborted")
	if len(f.aborted) != 1 {
		t.Fatalf("expected an abort, got %v", f.aborted)
	}

	// keep_on_failure keeps it; resume skips the parts already uploaded.
	f.failPart, f.failCount = 3, 1
	r := h.MustFail("s3_multipart_upload", s3Args(f, file, map[string]any{"max_retries": 0, "keep_on_failure": true}), "resume_upload_id=")
	m := regexp.MustCompile(`resume_upload_id="([^"]+)"`).FindStringSubmatch(r.Text)
	if m == nil || len(f.aborted) != 1 {
		t.Fatalf("no upload id or unexpected abort: %s %v", r.Text, f.aborted)
	}
	f.partPuts = nil
	r = h.MustOK("s3_multipart_upload", s3Args(f, file, map[string]any{"resume_upload_id": m[1]}))
	var out transferOut
	r.Decode(t, &out)
	if fmt.Sprint(f.partPuts) != "[3]" {
		t.Fatalf("resume uploaded parts %v, want [3]", f.partPuts)
	}
	if out.ResumedFrom != 10<<20 || out.BytesTransferred != 2<<20 || out.Meta["parts_skipped"].(float64) != 2 || out.Parts != 3 {
		t.Fatalf("resume result: resumed=%d bytes=%d meta=%v", out.ResumedFrom, out.BytesTransferred, out.Meta)
	}
	if out.File.SHA256 != sha(data) || !bytes.Equal(f.objects["dir/my file+1.bin"], data) {
		t.Fatal("content mismatch after resume")
	}
}

func TestS3Validation(t *testing.T) {
	f := newFakeS3(t)
	h := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateOptIn))
	file := h.WriteInput("a.bin", []byte("x"))
	args := s3Args(f, file, nil)
	h.MustFail("s3_multipart_upload", args, "blocked")
	delete(args, "aws")
	args["allow_private"] = true
	h.MustFail("s3_multipart_upload", args, "credentials are required")
	outside := filepath.Join(filepath.Dir(h.ReadDir), "outside.bin")
	os.WriteFile(outside, []byte("secret"), 0o644)
	args = s3Args(f, "../outside.bin", map[string]any{"allow_private": true})
	h.MustFail("s3_multipart_upload", args, "outside the allowed read directories")
	// A small file still works (single part below the minimum is allowed for the last part).
	r := h.MustOK("s3_multipart_upload", s3Args(f, file, map[string]any{"allow_private": true}))
	var out transferOut
	r.Decode(t, &out)
	if out.Parts != 1 || !bytes.Equal(f.objects["dir/my file+1.bin"], []byte("x")) {
		t.Fatalf("small upload: %+v", out)
	}
}
