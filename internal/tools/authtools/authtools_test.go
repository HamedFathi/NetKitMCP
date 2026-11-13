package authtools_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/authtools"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// fakeAS is an in-process OAuth2 authorization server.
type fakeAS struct {
	*httptest.Server
	mu          sync.Mutex
	counts      map[string]int
	challenges  map[string]string // code -> S256 challenge
	devicePolls int
	lastForm    url.Values
	lastBasic   bool
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{counts: map[string]int{}, challenges: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAS) count(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[k]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeAS) handle(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastForm = r.PostForm
	id, sec, basic := r.BasicAuth()
	f.lastBasic = basic
	if !basic {
		id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	confidential := id == "cid" && sec == "csecret"
	public := id == "public" && sec == ""
	if !confidential && !public {
		writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "bad client"})
		return
	}
	switch r.URL.Path {
	case "/device":
		writeJSON(w, 200, map[string]any{"device_code": "dev-123", "user_code": "ABCD-EFGH",
			"verification_uri": f.URL + "/activate", "verification_uri_complete": f.URL + "/activate?user_code=ABCD-EFGH",
			"expires_in": 600, "interval": 0})
		return
	case "/token":
	default:
		w.WriteHeader(404)
		return
	}
	g := r.PostForm.Get("grant_type")
	f.counts[g]++
	n := f.counts[g]
	tok := func(extra map[string]any) {
		out := map[string]any{"access_token": fmt.Sprintf("at-%s-%d", g, n), "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": fmt.Sprintf("rt-%s-%d", g, n), "scope": r.PostForm.Get("scope")}
		for k, v := range extra {
			out[k] = v
		}
		writeJSON(w, 200, out)
	}
	switch g {
	case "client_credentials":
		tok(nil)
	case "password":
		if r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		tok(map[string]any{"id_token": "idt"})
	case "refresh_token":
		if !strings.HasPrefix(r.PostForm.Get("refresh_token"), "rt-") {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		tok(nil)
	case auth.GrantTokenExchange:
		if r.PostForm.Get("subject_token") == "" || r.PostForm.Get("subject_token_type") == "" {
			writeJSON(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		tok(map[string]any{"issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "N_A"})
	case auth.GrantJWTBearer:
		if _, _, err := jwt.NewParser().ParseUnverified(r.PostForm.Get("assertion"), jwt.MapClaims{}); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		tok(nil)
	case "authorization_code":
		code := r.PostForm.Get("code")
		ch, ok := f.challenges[code]
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ch || r.PostForm.Get("redirect_uri") != "http://localhost/cb" {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		delete(f.challenges, code)
		tok(nil)
	case auth.GrantDeviceCode:
		f.devicePolls++
		if r.PostForm.Get("device_code") != "dev-123" {
			writeJSON(w, 400, map[string]any{"error": "expired_token"})
			return
		}
		if f.devicePolls < 3 {
			writeJSON(w, 400, map[string]any{"error": "authorization_pending"})
			return
		}
		tok(nil)
	default:
		writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
	}
}

func TestGetTokenGrants(t *testing.T) {
	f := newFakeAS(t)
	h := tooltest.New(t, "auth")
	base := map[string]any{"token_url": f.URL + "/token", "client_id": "cid", "client_secret": "csecret"}
	with := func(kv ...any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}

	r := h.MustOK("oauth2_get_token", with("scopes", []string{"read", "write"}))
	if r.Data["access_token"] != "at-client_credentials-1" || r.Data["scope"] != "read write" || r.Data["expiry"] == "" || r.Data["raw"] == nil {
		t.Fatalf("client_credentials: %s", r.Raw)
	}
	if strings.Contains(string(r.Raw), "csecret") {
		t.Fatal("client_secret echoed")
	}

	r = h.MustOK("oauth2_get_token", with("grant", "password", "username", "alice", "password", "pw", "auth_style", "body"))
	if r.Data["access_token"] != "at-password-1" || r.Data["id_token"] != "idt" || f.lastBasic {
		t.Fatalf("password: %s basic=%v", r.Raw, f.lastBasic)
	}
	h.MustFail("oauth2_get_token", with("grant", "password", "username", "alice", "password", "nope"), "invalid_grant")

	r = h.MustOK("oauth2_get_token", with("grant", "refresh_token", "refresh_token", "rt-x"))
	if r.Data["access_token"] != "at-refresh_token-1" {
		t.Fatalf("refresh: %s", r.Raw)
	}

	r = h.MustOK("oauth2_get_token", with("grant", "token_exchange", "subject_token", "abc", "audience", "api://b", "resource", "https://r.example"))
	if r.Data["issued_token_type"] == nil || f.lastForm.Get("audience") != "api://b" || f.lastForm.Get("resource") != "https://r.example" ||
		f.lastForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("token_exchange: %s form=%v", r.Raw, f.lastForm)
	}

	r = h.MustOK("oauth2_get_token", with("grant", "jwt_bearer", "jwt", map[string]any{"secret": "k", "iss": "me", "aud": []string{f.URL}}))
	if r.Data["access_token"] != "at-urn:ietf:params:oauth:grant-type:jwt-bearer-1" {
		t.Fatalf("jwt_bearer: %s", r.Raw)
	}

	h.MustFail("oauth2_get_token", map[string]any{"token_url": f.URL + "/token", "client_id": "cid", "client_secret": "bad"}, "invalid_client")
	h.MustFail("oauth2_get_token", map[string]any{"client_id": "cid"}, "token_url is required")
}

func TestGetTokenCache(t *testing.T) {
	f := newFakeAS(t)
	h := tooltest.New(t, "auth")
	args := map[string]any{"token_url": f.URL + "/token", "client_id": "cid", "client_secret": "csecret", "use_cache": true}
	r1 := h.MustOK("oauth2_get_token", args)
	r2 := h.MustOK("oauth2_get_token", args)
	if r1.Data["access_token"] != r2.Data["access_token"] || r2.Data["source"] != "cache" || f.count("client_credentials") != 1 {
		t.Fatalf("cache: %s / %s (requests %d)", r1.Raw, r2.Raw, f.count("client_credentials"))
	}

	// The same cache backs auth {type: oauth2} on other tools (via httpx).
	var got []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
	}))
	defer api.Close()
	a := &auth.Config{Type: "oauth2", OAuth2: &auth.OAuth2Config{TokenURL: f.URL + "/token", ClientID: "cid", ClientSecret: "csecret"}}
	c, err := h.Deps.NewHTTPClient(types.HTTPOptions{}, a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 2 {
		resp, err := c.Client.Get(api.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if len(got) != 2 || got[0] != "Bearer "+r1.Data["access_token"].(string) || got[1] != got[0] || f.count("client_credentials") != 1 {
		t.Fatalf("transport: %v (requests %d)", got, f.count("client_credentials"))
	}
}

func TestAuthCodePKCE(t *testing.T) {
	f := newFakeAS(t)
	h := tooltest.New(t, "auth")
	r := h.MustOK("oauth2_auth_url", map[string]any{
		"authorization_url": "https://idp.example.com/authorize?tenant=x", "client_id": "public",
		"redirect_uri": "http://localhost/cb", "scopes": []string{"openid", "profile"}, "extra_params": map[string]string{"prompt": "consent"},
	})
	var out struct {
		URL, State, CodeVerifier, CodeChallenge, Nonce string
	}
	out.URL, _ = r.Data["url"].(string)
	out.State, _ = r.Data["state"].(string)
	out.CodeVerifier, _ = r.Data["code_verifier"].(string)
	out.CodeChallenge, _ = r.Data["code_challenge"].(string)
	out.Nonce, _ = r.Data["nonce"].(string)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	sum := sha256.Sum256([]byte(out.CodeVerifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("code_challenge_method") != "S256" ||
		q.Get("state") != out.State || q.Get("tenant") != "x" || q.Get("prompt") != "consent" || q.Get("scope") != "openid profile" ||
		q.Get("nonce") != out.Nonce || q.Get("response_type") != "code" || len(out.CodeVerifier) < 43 {
		t.Fatalf("auth url: %s", r.Raw)
	}

	// The "user" approves: the server issues a code bound to the challenge.
	f.mu.Lock()
	f.challenges["code-1"] = q.Get("code_challenge")
	f.challenges["code-2"] = q.Get("code_challenge")
	f.mu.Unlock()

	// Wrong state in the pasted redirect URL is rejected.
	h.MustFail("oauth2_exchange_code", map[string]any{"token_url": f.URL + "/token", "client_id": "public",
		"redirect_url": "http://localhost/cb?code=code-1&state=evil", "state": out.State, "code_verifier": out.CodeVerifier}, "state mismatch")

	// Full redirect URL: code and redirect_uri are derived.
	r = h.MustOK("oauth2_exchange_code", map[string]any{"token_url": f.URL + "/token", "client_id": "public",
		"redirect_url": "http://localhost/cb?code=code-1&state=" + url.QueryEscape(out.State), "state": out.State, "code_verifier": out.CodeVerifier})
	if r.Data["access_token"] != "at-authorization_code-1" || f.lastForm.Get("client_id") != "public" {
		t.Fatalf("exchange: %s", r.Raw)
	}
	// A wrong verifier fails PKCE.
	h.MustFail("oauth2_exchange_code", map[string]any{"token_url": f.URL + "/token", "client_id": "public", "code": "code-2",
		"redirect_uri": "http://localhost/cb", "code_verifier": strings.Repeat("a", 43)}, "PKCE verification failed")
	// Authorization errors in the redirect are surfaced.
	h.MustFail("oauth2_exchange_code", map[string]any{"token_url": f.URL + "/token", "client_id": "public",
		"redirect_url": "http://localhost/cb?error=access_denied&error_description=nope"}, "access_denied")
}

func TestDeviceFlow(t *testing.T) {
	f := newFakeAS(t)
	h := tooltest.New(t, "auth")
	r := h.MustOK("oauth2_device_start", map[string]any{"device_authorization_url": f.URL + "/device", "client_id": "public", "scopes": []string{"a"}})
	if r.Data["device_code"] != "dev-123" || r.Data["user_code"] != "ABCD-EFGH" || r.Data["verification_uri_complete"] == nil {
		t.Fatalf("start: %s", r.Raw)
	}
	poll := map[string]any{"token_url": f.URL + "/token", "client_id": "public", "device_code": "dev-123", "interval_seconds": 0.2}

	// A short budget returns authorization_pending.
	p := map[string]any{"max_wait_seconds": 0.1}
	for k, v := range poll {
		p[k] = v
	}
	r = h.MustOK("oauth2_device_poll", p)
	if r.Data["status"] != "authorization_pending" || r.Data["next_interval_seconds"] == nil {
		t.Fatalf("pending: %s", r.Raw)
	}
	// Then polling continues until approval (third poll succeeds).
	r = h.MustOK("oauth2_device_poll", poll)
	if r.Data["status"] != "authorized" || r.Data["access_token"] != "at-urn:ietf:params:oauth:grant-type:device_code-3" || r.Data["polls"] != 2.0 {
		t.Fatalf("authorized: %s", r.Raw)
	}
	// Terminal errors are results.
	poll["device_code"] = "other"
	r = h.MustOK("oauth2_device_poll", poll)
	if r.Data["status"] != "expired_token" {
		t.Fatalf("expired: %s", r.Raw)
	}
}

func TestSSRFGuardOnTokenEndpoint(t *testing.T) {
	f := newFakeAS(t)
	h := tooltest.New(t, "auth", tooltest.WithPrivateMode(config.PrivateOptIn))
	args := map[string]any{"token_url": f.URL + "/token", "client_id": "cid", "client_secret": "csecret"}
	r := h.Call("oauth2_get_token", args)
	if !r.IsError {
		t.Fatalf("expected the guard to block a loopback token_url: %s", r.Text)
	}
	args["allow_private"] = true
	h.MustOK("oauth2_get_token", args)
}

// The auth layer reaches a server correctly through d.Auth.Transport.
func TestTransportAuthTypes(t *testing.T) {
	h := tooltest.New(t, "auth")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/basic":
			u, p, ok := r.BasicAuth()
			if !ok || u != "u" || p != "p" {
				w.WriteHeader(401)
				return
			}
		case "/bearer":
			if r.Header.Get("Authorization") != "Bearer tkn" {
				w.WriteHeader(401)
				return
			}
		case "/apikey":
			if r.Header.Get("X-Api-Key") != "k1" || r.URL.Query().Get("q") != "k2" {
				w.WriteHeader(401)
				return
			}
			if c, err := r.Cookie("sess"); err != nil || c.Value != "k3" {
				w.WriteHeader(401)
				return
			}
		case "/jwt":
			_, err := jwt.Parse(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
				func(*jwt.Token) (any, error) { return []byte("hmac"), nil }, jwt.WithValidMethods([]string{"HS256"}))
			if err != nil {
				w.WriteHeader(401)
				return
			}
		case "/digest":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Digest ") {
				w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n0nce", qop="auth", algorithm=SHA-256`)
				w.WriteHeader(401)
				return
			}
			if !strings.Contains(r.Header.Get("Authorization"), `username="u"`) {
				w.WriteHeader(403)
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok %s", body)
	}))
	defer srv.Close()

	env := h.Deps.AuthEnv(true)
	do := func(path string, a *auth.Config, apply func(*http.Request)) {
		t.Helper()
		rt, err := h.Deps.Auth.Transport(http.DefaultTransport, a, env)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), "POST", srv.URL+path, strings.NewReader("data"))
		if apply != nil {
			apply(req)
		}
		resp, err := (&http.Client{Transport: rt}).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != "ok data" {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
		}
	}
	do("/basic", &auth.Config{Type: "basic", Username: "u", Password: "p"}, nil)
	do("/bearer", &auth.Config{Type: "bearer", Token: "tkn"}, nil)
	// api_key three ways: chain three transports.
	rt1, _ := h.Deps.Auth.Transport(http.DefaultTransport, &auth.Config{Type: "api_key", Key: "X-Api-Key", Value: "k1"}, env)
	rt2, _ := h.Deps.Auth.Transport(rt1, &auth.Config{Type: "api_key", Key: "q", Value: "k2", In: "query"}, env)
	rt3, _ := h.Deps.Auth.Transport(rt2, &auth.Config{Type: "api_key", Key: "sess", Value: "k3", In: "cookie"}, env)
	resp, err := (&http.Client{Transport: rt3}).Post(srv.URL+"/apikey", "text/plain", strings.NewReader("data"))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("api_key: %v %v", err, resp)
	}
	resp.Body.Close()
	do("/jwt", &auth.Config{Type: "jwt", JWT: &auth.JWTConfig{Secret: "hmac", Issuer: "me"}}, nil)
	do("/digest", &auth.Config{Type: "digest", Username: "u", Password: "p"}, nil)
	// No GetBody: the digest retry still resends the body.
	do("/digest", &auth.Config{Type: "digest", Username: "u", Password: "p"}, func(r *http.Request) { r.GetBody = nil })
}

func TestToolsListed(t *testing.T) {
	h := tooltest.New(t, "auth")
	names := strings.Join(h.ListTools(), ",")
	for _, n := range []string{"oauth2_get_token", "oauth2_auth_url", "oauth2_exchange_code", "oauth2_device_start", "oauth2_device_poll"} {
		if !strings.Contains(names, n) {
			t.Fatalf("missing %s in %s", n, names)
		}
	}
}
