package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// maxBufferedBody bounds bodies that signers must buffer because the request
// has no GetBody (form parameters, OAuth1 body hashes, Hawk payload hashes).
const maxBufferedBody = 16 << 20

// hasBody reports whether the request carries a body.
func hasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody
}

// readBody returns the full request body without consuming it: it uses
// GetBody when available, otherwise buffers the body (bounded) and installs
// a replayable copy on the request.
func readBody(req *http.Request) ([]byte, error) {
	if !hasBody(req) {
		return nil, nil
	}
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, maxBufferedBody+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxBufferedBody {
			return nil, fmt.Errorf("request body exceeds %d bytes and cannot be signed", maxBufferedBody)
		}
		return b, nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxBufferedBody+1))
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(b) > maxBufferedBody {
		return nil, fmt.Errorf("request body exceeds %d bytes and cannot be signed (provide a replayable body)", maxBufferedBody)
	}
	setBody(req, b)
	return b, nil
}

// setBody installs a replayable in-memory body.
func setBody(req *http.Request, b []byte) {
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	req.ContentLength = int64(len(b))
}

// hashBody streams the body through h using GetBody (no buffering). ok is
// false when the body cannot be re-read without consuming it.
func hashBody(req *http.Request, h hash.Hash) (ok bool, err error) {
	if !hasBody(req) {
		return true, nil
	}
	if req.GetBody == nil {
		return false, nil
	}
	rc, err := req.GetBody()
	if err != nil {
		return false, err
	}
	defer rc.Close()
	if _, err := io.Copy(h, rc); err != nil {
		return false, err
	}
	return true, nil
}

// isForm reports whether the request body is application/x-www-form-urlencoded.
func isForm(req *http.Request) bool {
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	return strings.HasPrefix(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// randomString returns n random alphanumeric characters.
func randomString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// randomURLSafe returns n random bytes base64url encoded without padding.
func randomURLSafe(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
