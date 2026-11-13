package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// edgeGridSigner implements Akamai EdgeGrid (EG1-HMAC-SHA256) signing.
type edgeGridSigner struct{ cfg *EdgeGridConfig }

func newEdgeGridSigner(cfg *EdgeGridConfig) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth akamai_edgegrid: the edgegrid object is required")
	}
	if cfg.ClientToken == "" || cfg.ClientSecret == "" || cfg.AccessToken == "" {
		return nil, fmt.Errorf("auth akamai_edgegrid: client_token, client_secret and access_token are required")
	}
	return &edgeGridSigner{cfg: cfg}, nil
}

func hmacSHA256B64(key, data string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// EdgeGridRequest are the inputs of an EdgeGrid signature.
type EdgeGridRequest struct {
	Method      string
	Scheme      string
	Host        string
	PathQuery   string
	Headers     http.Header
	Body        []byte
	Timestamp   string
	Nonce       string
	ClientToken string
	AccessToken string
	Secret      string
	MaxBody     int
	SignHeaders []string
}

// EdgeGridAuthorization computes the Authorization header value.
func EdgeGridAuthorization(r EdgeGridRequest) string {
	authHeader := fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		r.ClientToken, r.AccessToken, r.Timestamp, r.Nonce)
	var canon []string
	for _, name := range r.SignHeaders {
		v := r.Headers.Get(name)
		if v == "" {
			continue
		}
		canon = append(canon, strings.ToLower(name)+":"+strings.Join(strings.Fields(v), " "))
	}
	contentHash := ""
	if strings.EqualFold(r.Method, "POST") && len(r.Body) > 0 {
		b := r.Body
		max := r.MaxBody
		if max <= 0 {
			max = 131072
		}
		if len(b) > max {
			b = b[:max]
		}
		sum := sha256.Sum256(b)
		contentHash = base64.StdEncoding.EncodeToString(sum[:])
	}
	data := strings.Join([]string{
		strings.ToUpper(r.Method),
		strings.ToLower(r.Scheme),
		strings.ToLower(r.Host),
		r.PathQuery,
		strings.Join(canon, "\t"),
		contentHash,
		authHeader,
	}, "\t")
	signingKey := hmacSHA256B64(r.Secret, r.Timestamp)
	return authHeader + "signature=" + hmacSHA256B64(signingKey, data)
}

// Sign implements Signer.
func (s *edgeGridSigner) Sign(_ context.Context, req *http.Request) error {
	c := s.cfg
	ts := c.Timestamp
	if ts == "" {
		ts = now().UTC().Format("20060102T15:04:05+0000")
	}
	nonce := c.Nonce
	if nonce == "" {
		nonce = newUUID()
	}
	var body []byte
	if strings.EqualFold(req.Method, "POST") && hasBody(req) {
		b, err := readBody(req)
		if err != nil {
			return err
		}
		body = b
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	pq := req.URL.EscapedPath()
	if pq == "" {
		pq = "/"
	}
	if req.URL.RawQuery != "" {
		pq += "?" + req.URL.RawQuery
	}
	req.Header.Set("Authorization", EdgeGridAuthorization(EdgeGridRequest{
		Method:      req.Method,
		Scheme:      req.URL.Scheme,
		Host:        host,
		PathQuery:   pq,
		Headers:     req.Header,
		Body:        body,
		Timestamp:   ts,
		Nonce:       nonce,
		ClientToken: c.ClientToken,
		AccessToken: c.AccessToken,
		Secret:      c.ClientSecret,
		MaxBody:     c.MaxBody,
		SignHeaders: c.HeadersToSign,
	}))
	return nil
}

// newUUID returns a random RFC 4122 version 4 UUID.
func newUUID() string {
	b := randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
