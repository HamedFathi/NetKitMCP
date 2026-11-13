package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/golang-jwt/jwt/v5"
)

func pemKey(t *testing.T, k any) (string, any) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	var pub any
	switch v := k.(type) {
	case *rsa.PrivateKey:
		pub = &v.PublicKey
	case *ecdsa.PrivateKey:
		pub = &v.PublicKey
	case ed25519.PrivateKey:
		pub = v.Public()
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), pub
}

func TestJWTSigner(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	rsaPEM, rsaPub := pemKey(t, rk)
	ecPEM, ecPub := pemKey(t, ek)
	edPEM, edPub := pemKey(t, edk)

	cases := []struct {
		alg, key, secret string
		verify           any
	}{
		{"HS256", "", "s3cret", []byte("s3cret")},
		{"HS512", "", "s3cret", []byte("s3cret")},
		{"RS256", rsaPEM, "", rsaPub},
		{"PS384", rsaPEM, "", rsaPub},
		{"ES256", ecPEM, "", ecPub},
		{"EdDSA", edPEM, "", edPub},
	}
	for _, tc := range cases {
		c := &Config{Type: "jwt", JWT: &JWTConfig{Algorithm: tc.alg, Key: tc.key, Secret: tc.secret, KeyID: "k1",
			Issuer: "me", Audience: []string{"you"}, Claims: map[string]any{"role": "admin"}}}
		req := mustReq(t, "GET", "http://h/", "")
		sign(t, c, req)
		h := req.Header.Get("Authorization")
		tokStr, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			t.Fatalf("%s: header %q", tc.alg, h)
		}
		tok, err := jwt.Parse(tokStr, func(*jwt.Token) (any, error) { return tc.verify, nil }, jwt.WithValidMethods([]string{tc.alg}))
		if err != nil {
			t.Fatalf("%s: verify: %v", tc.alg, err)
		}
		cl := tok.Claims.(jwt.MapClaims)
		if cl["iss"] != "me" || cl["aud"] != "you" || cl["role"] != "admin" || tok.Header["kid"] != "k1" {
			t.Fatalf("%s: claims %v header %v", tc.alg, cl, tok.Header)
		}
	}

	// Query placement, custom header, pre-built token, base64 secret.
	req := mustReq(t, "GET", "http://h/?a=1", "")
	sign(t, &Config{Type: "jwt", JWT: &JWTConfig{Token: "pre.built.jwt", QueryKey: "jwt"}}, req)
	if req.URL.Query().Get("jwt") != "pre.built.jwt" || req.URL.Query().Get("a") != "1" {
		t.Fatalf("query: %s", req.URL.RawQuery)
	}
	req = mustReq(t, "GET", "http://h/", "")
	sign(t, &Config{Type: "jwt", JWT: &JWTConfig{Secret: base64.StdEncoding.EncodeToString([]byte("raw")), SecretB64: true, Header: "X-JWT"}}, req)
	if _, err := jwt.Parse(req.Header.Get("X-JWT"), func(*jwt.Token) (any, error) { return []byte("raw"), nil }); err != nil {
		t.Fatalf("custom header: %v (%q)", err, req.Header.Get("X-JWT"))
	}
	if _, err := NewManager().Signer(&Config{Type: "jwt", JWT: &JWTConfig{Algorithm: "RS256"}}, Env{}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestASAP(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	p, pub := pemKey(t, rk)
	req := mustReq(t, "GET", "http://h/", "")
	sign(t, &Config{Type: "asap", ASAP: &ASAPConfig{Issuer: "svc-a", KeyID: "svc-a/key1", PrivateKey: p, Audience: []string{"svc-b"}, ExpiresIn: 99999}}, req)
	tok, err := jwt.Parse(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	cl := tok.Claims.(jwt.MapClaims)
	if cl["iss"] != "svc-a" || cl["sub"] != "svc-a" || cl["aud"] != "svc-b" || cl["jti"] == "" || tok.Header["kid"] != "svc-a/key1" {
		t.Fatalf("claims %v header %v", cl, tok.Header)
	}
	if exp, iat := cl["exp"].(float64), cl["iat"].(float64); exp-iat != 3600 {
		t.Fatalf("lifetime %v not capped to 3600", exp-iat)
	}
}

// fakeTokenServer is a minimal OAuth2 token endpoint.
type fakeTokenServer struct {
	*httptest.Server
	requests atomic.Int32
	lastForm atomic.Value
	expires  int
}

func newFakeTokenServer(t *testing.T) *fakeTokenServer {
	f := &fakeTokenServer{expires: 3600}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := f.requests.Add(1)
		r.ParseForm()
		f.lastForm.Store(r.PostForm.Encode())
		id, sec, ok := r.BasicAuth()
		if !ok {
			id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		w.Header().Set("Content-Type", "application/json")
		if id != "cid" || sec != "csecret" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		g := r.PostForm.Get("grant_type")
		if g == "refresh_token" && r.PostForm.Get("refresh_token") == "bad" {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"expired"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("tok-%s-%d", g, n), "token_type": "bearer",
			"expires_in": f.expires, "refresh_token": fmt.Sprintf("rt-%d", n), "scope": r.PostForm.Get("scope"),
		})
	}))
	t.Cleanup(f.Close)
	return f
}

func TestOAuth2CacheAndRefresh(t *testing.T) {
	f := newFakeTokenServer(t)
	env := Env{TokenClient: func() *http.Client { return f.Client() }}
	m := NewManager()
	cfg := &Config{Type: "oauth2", OAuth2: &OAuth2Config{TokenURL: f.URL, ClientID: "cid", ClientSecret: "csecret", Scopes: []string{"a", "b"}}}

	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	defer api.Close()
	rt, err := m.Transport(http.DefaultTransport, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: rt}
	for range 2 {
		resp, err := cl.Get(api.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if f.requests.Load() != 1 || seen[0] != "Bearer tok-client_credentials-1" || seen[1] != seen[0] {
		t.Fatalf("expected one cached token, got %d requests, headers %v", f.requests.Load(), seen)
	}
	if !strings.Contains(f.lastForm.Load().(string), "scope=a+b") {
		t.Fatalf("form: %s", f.lastForm.Load())
	}

	// Expire the cache: the refresh token is used.
	saved := now
	now = func() time.Time { return saved().Add(2 * time.Hour) }
	defer func() { now = saved }()
	tok, src, err := m.OAuth2Token(context.Background(), cfg.OAuth2, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceRefreshed || tok.AccessToken != "tok-refresh_token-2" || !strings.Contains(f.lastForm.Load().(string), "refresh_token=rt-1") {
		t.Fatalf("refresh: %s %s %s", src, tok.AccessToken, f.lastForm.Load())
	}

	// A failed refresh falls back to the original grant.
	m.store(cacheKey(cfg.OAuth2), &Token{AccessToken: "old", RefreshToken: "bad", Expiry: time.Unix(1, 0)})
	tok, src, err = m.OAuth2Token(context.Background(), cfg.OAuth2, env, true)
	if err != nil || src != SourceRequested || !strings.HasPrefix(tok.AccessToken, "tok-client_credentials-") {
		t.Fatalf("fallback: %v %s %+v", err, src, tok)
	}

	// Body auth style and error reporting.
	bad := &OAuth2Config{TokenURL: f.URL, ClientID: "cid", ClientSecret: "wrong", AuthStyle: "body"}
	_, _, err = m.OAuth2Token(context.Background(), bad, env, false)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "invalid_client" || te.Status != 401 {
		t.Fatalf("expected invalid_client, got %v", err)
	}

	// Passthrough.
	tok, src, _ = m.OAuth2Token(context.Background(), &OAuth2Config{Grant: "access_token", AccessToken: "xyz", TokenType: "MAC"}, env, true)
	if src != SourcePassthrough || tok.AuthorizationValue("MAC") != "MAC xyz" {
		t.Fatalf("passthrough: %s %+v", src, tok)
	}
}

func TestOAuth2Grants(t *testing.T) {
	f := newFakeTokenServer(t)
	env := Env{TokenClient: func() *http.Client { return f.Client() }}
	m := NewManager()
	cases := []struct {
		cfg  OAuth2Config
		want []string
	}{
		{OAuth2Config{Grant: "password", Username: "u", Password: "p"}, []string{"grant_type=password", "username=u", "password=p"}},
		{OAuth2Config{Grant: "jwt_bearer", JWT: &JWTConfig{Secret: "k", Issuer: "i"}}, []string{"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer", "assertion=ey"}},
		{OAuth2Config{Grant: "token_exchange", SubjectToken: "st", Audience: "aud1", Resource: "https://r", RequestedType: "urn:x"},
			[]string{"subject_token=st", "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token", "audience=aud1", "resource=https%3A%2F%2Fr", "requested_token_type=urn%3Ax"}},
		{OAuth2Config{Grant: "refresh_token", RefreshToken: "r0", ExtraParams: map[string]string{"x": "y"}}, []string{"grant_type=refresh_token", "refresh_token=r0", "x=y"}},
	}
	for _, tc := range cases {
		c := tc.cfg
		c.TokenURL, c.ClientID, c.ClientSecret = f.URL, "cid", "csecret"
		if _, _, err := m.OAuth2Token(context.Background(), &c, env, false); err != nil {
			t.Fatalf("%s: %v", c.Grant, err)
		}
		form := f.lastForm.Load().(string)
		for _, w := range tc.want {
			if !strings.Contains(form, w) {
				t.Fatalf("%s: form %s missing %s", c.Grant, form, w)
			}
		}
	}
}

func TestHeadersHelper(t *testing.T) {
	h, u, err := NewManager().Headers(context.Background(), &Config{Type: "api_key", Key: "k", Value: "v", In: "query"}, Env{}, "GET", "wss://h/p")
	if err != nil || u != "wss://h/p?k=v" || len(h) != 0 {
		t.Fatalf("%v %s %v", err, u, h)
	}
	h, _, err = NewManager().Headers(context.Background(), &Config{Type: "hawk", Hawk: &HawkConfig{ID: "i", Key: "k"}}, Env{}, "GET", "wss://h/p")
	if err != nil || !strings.HasPrefix(h.Get("Authorization"), "Hawk id=\"i\"") {
		t.Fatalf("%v %v", err, h)
	}
	if _, _, err := NewManager().Headers(context.Background(), &Config{Type: "digest"}, Env{}, "GET", "http://h"); err == nil {
		t.Fatal("digest should need a challenge")
	}
}

// ntlmChallenge builds a minimal NTLM CHALLENGE_MESSAGE.
func ntlmChallenge() []byte {
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(2))
	binary.Write(&b, binary.LittleEndian, [2]uint16{0, 0})
	binary.Write(&b, binary.LittleEndian, uint32(48))
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001|0x00000200|0x00080000|0x00800000))
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	b.Write(make([]byte, 8))
	binary.Write(&b, binary.LittleEndian, [2]uint16{4, 4})
	binary.Write(&b, binary.LittleEndian, uint32(48))
	b.Write([]byte{0, 0, 0, 0}) // MsvAvEOL
	return b.Bytes()
}

func TestNTLMHandshake(t *testing.T) {
	var legs atomic.Int32
	user16 := func(s string) []byte {
		var b bytes.Buffer
		for _, r := range utf16.Encode([]rune(s)) {
			binary.Write(&b, binary.LittleEndian, r)
		}
		return b.Bytes()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h := r.Header.Get("Authorization")
		legs.Add(1)
		switch {
		case h == "":
			w.Header().Set("WWW-Authenticate", "NTLM")
			w.WriteHeader(401)
		case strings.HasPrefix(h, "NTLM "):
			msg, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "NTLM "))
			if len(msg) < 12 || string(msg[:8]) != "NTLMSSP\x00" {
				w.WriteHeader(400)
				return
			}
			switch binary.LittleEndian.Uint32(msg[8:12]) {
			case 1:
				w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ntlmChallenge()))
				w.WriteHeader(401)
			case 3:
				if !bytes.Contains(msg, user16("alice")) || !bytes.Contains(msg, user16("CORP")) {
					w.WriteHeader(403)
					return
				}
				fmt.Fprintf(w, "hello %s", body)
			}
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	rt, err := NewManager().Transport(http.DefaultTransport, &Config{Type: "ntlm", Username: "alice", Password: "pw", Domain: "CORP"}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Post(srv.URL, "text/plain", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "hello body" || legs.Load() != 3 {
		t.Fatalf("ntlm: %d %q legs=%d", resp.StatusCode, b, legs.Load())
	}
}

func TestNegotiateConfig(t *testing.T) {
	cfg, err := krb5Config(&KerberosConfig{Realm: "EXAMPLE.COM", KDC: "kdc.example.com"}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.DefaultRealm != "EXAMPLE.COM" || len(cfg.Realms) != 1 || cfg.Realms[0].KDC[0] != "kdc.example.com:88" {
		t.Fatalf("config: %+v", cfg.Realms)
	}
	if _, err := NewManager().Transport(nil, &Config{Type: "negotiate", Username: "u"}, Env{}); err == nil {
		t.Fatal("expected error without realm")
	}
	// The SSRF hook is consulted for KDCs.
	env := Env{CheckAddress: func(hp string) error { return fmt.Errorf("blocked %s", hp) }}
	_, err = NewManager().Transport(nil, &Config{Type: "negotiate", Username: "u", Password: "p",
		Kerberos: &KerberosConfig{Realm: "EXAMPLE.COM", KDC: "127.0.0.1:1"}}, env)
	if err == nil || !strings.Contains(err.Error(), "blocked 127.0.0.1:1") {
		t.Fatalf("expected KDC check, got %v", err)
	}
	// An unreachable KDC fails the request with a clear error.
	rt, err := NewManager().Transport(http.DefaultTransport, &Config{Type: "negotiate", Username: "u", Password: "p",
		Kerberos: &KerberosConfig{Realm: "EXAMPLE.COM", KDC: "127.0.0.1:1"}}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: rt}).Get("http://127.0.0.1:1/")
	if err == nil || !strings.Contains(err.Error(), "auth negotiate") {
		t.Fatalf("expected negotiate error, got %v", err)
	}
}
