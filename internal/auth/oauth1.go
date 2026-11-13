package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// oauth1Signer implements OAuth 1.0a (RFC 5849) request signing.
type oauth1Signer struct {
	cfg    *OAuth1Config
	method string
	rsaKey *rsa.PrivateKey
}

func newOAuth1Signer(cfg *OAuth1Config, env Env) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth oauth1: the oauth1 object is required")
	}
	if cfg.ConsumerKey == "" {
		return nil, fmt.Errorf("auth oauth1: consumer_key is required")
	}
	s := &oauth1Signer{cfg: cfg, method: strings.ToUpper(cfg.SignatureMethod)}
	if s.method == "" {
		s.method = "HMAC-SHA1"
	}
	switch s.method {
	case "HMAC-SHA1", "HMAC-SHA256", "PLAINTEXT":
	case "RSA-SHA1", "RSA-SHA256":
		if cfg.PrivateKey == "" {
			return nil, fmt.Errorf("auth oauth1: private_key is required for %s", s.method)
		}
		pemBytes, err := LoadKey(env, cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("auth oauth1 private_key: %w", err)
		}
		k, err := parseRSAPrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("auth oauth1 private_key: %w", err)
		}
		s.rsaKey = k
	default:
		return nil, fmt.Errorf("auth oauth1: unsupported signature_method %q", cfg.SignatureMethod)
	}
	return s, nil
}

func parseRSAPrivateKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rk, nil
}

func (s *oauth1Signer) hashFunc() func() hash.Hash {
	if strings.HasSuffix(s.method, "SHA256") {
		return sha256.New
	}
	return sha1.New
}

// Sign implements Signer.
func (s *oauth1Signer) Sign(_ context.Context, req *http.Request) error {
	c := s.cfg
	oauth := map[string]string{
		"oauth_consumer_key":     c.ConsumerKey,
		"oauth_signature_method": s.method,
		"oauth_version":          "1.0",
	}
	ts := c.Timestamp
	if ts == 0 {
		ts = now().Unix()
	}
	oauth["oauth_timestamp"] = strconv.FormatInt(ts, 10)
	nonce := c.Nonce
	if nonce == "" {
		nonce = randomString(32)
	}
	oauth["oauth_nonce"] = nonce
	if c.Token != "" {
		oauth["oauth_token"] = c.Token
	}
	if c.Callback != "" {
		oauth["oauth_callback"] = c.Callback
	}
	if c.Verifier != "" {
		oauth["oauth_verifier"] = c.Verifier
	}

	// Collect request parameters: query plus form body (RFC 5849 §3.4.1.3).
	var params [][2]string
	for k, vs := range req.URL.Query() {
		for _, v := range vs {
			params = append(params, [2]string{k, v})
		}
	}
	form := hasBody(req) && isForm(req)
	if form {
		b, err := readBody(req)
		if err != nil {
			return err
		}
		vals, err := url.ParseQuery(string(b))
		if err != nil {
			return fmt.Errorf("oauth1: parse form body: %w", err)
		}
		for k, vs := range vals {
			for _, v := range vs {
				params = append(params, [2]string{k, v})
			}
		}
	} else if c.BodyHash {
		h := s.hashFunc()()
		if hasBody(req) {
			b, err := readBody(req)
			if err != nil {
				return err
			}
			h.Write(b)
		}
		oauth["oauth_body_hash"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	for k, v := range oauth {
		params = append(params, [2]string{k, v})
	}

	sig, err := s.signature(req.Method, req.URL, params)
	if err != nil {
		return err
	}
	oauth["oauth_signature"] = sig

	keys := make([]string, 0, len(oauth))
	for k := range oauth {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if c.InQuery {
		q := req.URL.RawQuery
		var parts []string
		for _, k := range keys {
			parts = append(parts, percentEncode(k)+"="+percentEncode(oauth[k]))
		}
		if q != "" {
			q += "&"
		}
		req.URL.RawQuery = q + strings.Join(parts, "&")
		return nil
	}
	var parts []string
	if c.Realm != "" {
		parts = append(parts, `realm="`+percentEncode(c.Realm)+`"`)
	}
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+`="`+percentEncode(oauth[k])+`"`)
	}
	req.Header.Set("Authorization", "OAuth "+strings.Join(parts, ", "))
	return nil
}

// signature computes oauth_signature for the given parameters.
func (s *oauth1Signer) signature(method string, u *url.URL, params [][2]string) (string, error) {
	key := percentEncode(s.cfg.ConsumerSecret) + "&" + percentEncode(s.cfg.TokenSecret)
	if s.method == "PLAINTEXT" {
		return key, nil
	}
	base := OAuth1BaseString(method, u, params)
	switch s.method {
	case "HMAC-SHA1", "HMAC-SHA256":
		m := hmac.New(s.hashFunc(), []byte(key))
		m.Write([]byte(base))
		return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
	default: // RSA
		h := s.hashFunc()()
		h.Write([]byte(base))
		ch := crypto.SHA1
		if strings.HasSuffix(s.method, "SHA256") {
			ch = crypto.SHA256
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.rsaKey, ch, h.Sum(nil))
		if err != nil {
			return "", fmt.Errorf("oauth1 rsa sign: %w", err)
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	}
}

// OAuth1BaseString builds the RFC 5849 §3.4.1 signature base string.
// params must include the oauth_* protocol parameters (except
// oauth_signature), query parameters and form body parameters.
func OAuth1BaseString(method string, u *url.URL, params [][2]string) string {
	enc := make([][2]string, 0, len(params))
	for _, p := range params {
		if p[0] == "oauth_signature" || p[0] == "realm" {
			continue
		}
		enc = append(enc, [2]string{percentEncode(p[0]), percentEncode(p[1])})
	}
	sort.Slice(enc, func(i, j int) bool {
		if enc[i][0] != enc[j][0] {
			return enc[i][0] < enc[j][0]
		}
		return enc[i][1] < enc[j][1]
	})
	pairs := make([]string, len(enc))
	for i, p := range enc {
		pairs[i] = p[0] + "=" + p[1]
	}
	return strings.ToUpper(method) + "&" + percentEncode(baseURI(u)) + "&" + percentEncode(strings.Join(pairs, "&"))
}

// baseURI returns scheme://host[:port]/path with default ports removed.
func baseURI(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// percentEncode encodes per RFC 3986 (unreserved characters kept).
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
