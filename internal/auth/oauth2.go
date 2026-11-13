package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Grant type URNs.
const (
	GrantJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantDeviceCode    = "urn:ietf:params:oauth:grant-type:device_code"
	TokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"
)

// expirySkew refreshes tokens slightly before they expire.
const expirySkew = 30 * time.Second

// maxTokenResponse bounds token endpoint responses.
const maxTokenResponse = 1 << 20

// Token is an OAuth2 token endpoint response.
type Token struct {
	AccessToken     string         `json:"access_token"`
	TokenType       string         `json:"token_type,omitempty"`
	RefreshToken    string         `json:"refresh_token,omitempty"`
	ExpiresIn       int64          `json:"expires_in,omitempty"`
	Expiry          time.Time      `json:"expiry,omitzero"`
	Scope           string         `json:"scope,omitempty"`
	IDToken         string         `json:"id_token,omitempty"`
	IssuedTokenType string         `json:"issued_token_type,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
}

// Expired reports whether the token is (about to be) expired.
func (t *Token) Expired() bool {
	return !t.Expiry.IsZero() && now().Add(expirySkew).After(t.Expiry)
}

// AuthorizationValue returns the Authorization header value for the token.
// override replaces the token type prefix.
func (t *Token) AuthorizationValue(override string) string {
	typ := override
	if typ == "" {
		typ = t.TokenType
	}
	switch strings.ToLower(typ) {
	case "", "bearer", "n_a":
		typ = "Bearer"
	}
	return typ + " " + t.AccessToken
}

// TokenError is an error response from an OAuth2 endpoint (RFC 6749 §5.2).
type TokenError struct {
	Status      int            `json:"status"`
	Code        string         `json:"error,omitempty"`
	Description string         `json:"error_description,omitempty"`
	URI         string         `json:"error_uri,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
	Body        string         `json:"body,omitempty"`
}

func (e *TokenError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "oauth2 endpoint returned HTTP %d", e.Status)
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if e.Description != "" {
		b.WriteString(" (" + e.Description + ")")
	}
	if e.Code == "" && e.Body != "" {
		body := e.Body
		if len(body) > 300 {
			body = body[:300] + "..."
		}
		b.WriteString(": " + body)
	}
	return b.String()
}

// ClientAuth describes how the client authenticates to an OAuth2 endpoint.
type ClientAuth struct {
	ClientID     string
	ClientSecret string
	// Style is "header" (HTTP Basic, default) or "body".
	Style string
}

// PostForm posts a form to an OAuth2 endpoint with client authentication and
// decodes the response (JSON or form-encoded). Non-2xx responses are
// returned as *TokenError.
func PostForm(ctx context.Context, client *http.Client, endpoint string, ca ClientAuth, form url.Values) (map[string]any, error) {
	if client == nil {
		return nil, fmt.Errorf("oauth2: no HTTP client configured")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("oauth2: endpoint URL is required")
	}
	f := url.Values{}
	for k, v := range form {
		f[k] = append([]string(nil), v...)
	}
	style := strings.ToLower(ca.Style)
	useHeader := ca.ClientSecret != "" && (style == "" || style == "header" || style == "basic")
	if !useHeader {
		if ca.ClientID != "" {
			f.Set("client_id", ca.ClientID)
		}
		if ca.ClientSecret != "" {
			f.Set("client_secret", ca.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(f.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useHeader {
		req.SetBasicAuth(url.QueryEscape(ca.ClientID), url.QueryEscape(ca.ClientSecret))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: request to %s failed: %w", redactURL(endpoint), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, fmt.Errorf("oauth2: read response: %w", err)
	}
	raw := decodeTokenBody(resp.Header.Get("Content-Type"), body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		te := &TokenError{Status: resp.StatusCode, Raw: raw}
		if raw != nil {
			te.Code, _ = raw["error"].(string)
			te.Description, _ = raw["error_description"].(string)
			te.URI, _ = raw["error_uri"].(string)
		}
		if te.Code == "" {
			te.Body = string(body)
		}
		return nil, te
	}
	if raw == nil {
		return nil, fmt.Errorf("oauth2: could not decode response (HTTP %d, content-type %q)", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// Some servers (GitHub) report errors with HTTP 200.
	if code, ok := raw["error"].(string); ok && code != "" {
		te := &TokenError{Status: resp.StatusCode, Code: code, Raw: raw}
		te.Description, _ = raw["error_description"].(string)
		te.URI, _ = raw["error_uri"].(string)
		return nil, te
	}
	return raw, nil
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(invalid URL)"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func decodeTokenBody(contentType string, body []byte) map[string]any {
	mt, _, _ := mime.ParseMediaType(contentType)
	var raw map[string]any
	if json.Unmarshal(body, &raw) == nil {
		return raw
	}
	if mt == "application/x-www-form-urlencoded" || mt == "text/plain" || mt == "" {
		vals, err := url.ParseQuery(strings.TrimSpace(string(body)))
		if err == nil && len(vals) > 0 {
			raw = map[string]any{}
			for k, v := range vals {
				if len(v) > 0 {
					raw[k] = v[0]
				}
			}
			return raw
		}
	}
	return nil
}

// ParseToken builds a Token from a decoded token response.
func ParseToken(raw map[string]any) (*Token, error) {
	t := &Token{Raw: raw}
	t.AccessToken = str(raw["access_token"])
	t.TokenType = str(raw["token_type"])
	t.RefreshToken = str(raw["refresh_token"])
	t.Scope = str(raw["scope"])
	t.IDToken = str(raw["id_token"])
	t.IssuedTokenType = str(raw["issued_token_type"])
	t.ExpiresIn = num(raw["expires_in"])
	if t.ExpiresIn > 0 {
		t.Expiry = now().Add(time.Duration(t.ExpiresIn) * time.Second).UTC().Truncate(time.Second)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("oauth2: response has no access_token")
	}
	return t, nil
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case []any:
		parts := make([]string, 0, len(x))
		for _, p := range x {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprint(x)
	}
}

func num(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseFloat(x, 64)
		return int64(n)
	}
	return 0
}

// clientAuth returns the client authentication for a config.
func (c *OAuth2Config) clientAuth() ClientAuth {
	return ClientAuth{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Style: c.AuthStyle}
}

// GrantName normalises the grant (default client_credentials).
func (c *OAuth2Config) GrantName() string {
	g := strings.ToLower(strings.TrimSpace(c.Grant))
	switch g {
	case "":
		return "client_credentials"
	case "jwt-bearer", GrantJWTBearer:
		return "jwt_bearer"
	case "token-exchange", GrantTokenExchange:
		return "token_exchange"
	case "refresh", "refresh-token":
		return "refresh_token"
	}
	return g
}

// addCommon adds scope, audience, resource and extra params.
func (c *OAuth2Config) addCommon(f url.Values) {
	if len(c.Scopes) > 0 {
		f.Set("scope", strings.Join(c.Scopes, " "))
	}
	if c.Audience != "" {
		f.Set("audience", c.Audience)
	}
	if c.Resource != "" {
		f.Set("resource", c.Resource)
	}
	for k, v := range c.ExtraParams {
		f.Set(k, v)
	}
}

// GrantForm builds the token request form for the configured grant.
func GrantForm(c *OAuth2Config, env Env) (url.Values, error) {
	f := url.Values{}
	switch g := c.GrantName(); g {
	case "client_credentials":
		f.Set("grant_type", "client_credentials")
	case "password":
		if c.Username == "" {
			return nil, fmt.Errorf("oauth2 password grant: username is required")
		}
		f.Set("grant_type", "password")
		f.Set("username", c.Username)
		f.Set("password", c.Password)
	case "refresh_token":
		if c.RefreshToken == "" {
			return nil, fmt.Errorf("oauth2 refresh_token grant: refresh_token is required")
		}
		f.Set("grant_type", "refresh_token")
		f.Set("refresh_token", c.RefreshToken)
	case "jwt_bearer":
		a := c.Assertion
		if a == "" {
			if c.JWT == nil {
				return nil, fmt.Errorf("oauth2 jwt_bearer grant: assertion or jwt settings are required")
			}
			s, err := SignJWT(c.JWT, env)
			if err != nil {
				return nil, fmt.Errorf("oauth2 jwt_bearer assertion: %w", err)
			}
			a = s
		}
		f.Set("grant_type", GrantJWTBearer)
		f.Set("assertion", a)
	case "token_exchange":
		if c.SubjectToken == "" {
			return nil, fmt.Errorf("oauth2 token_exchange grant: subject_token is required")
		}
		f.Set("grant_type", GrantTokenExchange)
		f.Set("subject_token", c.SubjectToken)
		stt := c.SubjectTokenType
		if stt == "" {
			stt = TokenTypeAccess
		}
		f.Set("subject_token_type", stt)
		if c.ActorToken != "" {
			f.Set("actor_token", c.ActorToken)
			att := c.ActorTokenType
			if att == "" {
				att = TokenTypeAccess
			}
			f.Set("actor_token_type", att)
		}
		if c.RequestedType != "" {
			f.Set("requested_token_type", c.RequestedType)
		}
	default:
		return nil, fmt.Errorf("oauth2: unsupported grant %q (client_credentials, password, refresh_token, jwt_bearer, token_exchange, access_token)", c.Grant)
	}
	c.addCommon(f)
	return f, nil
}

// RequestToken performs one token request for the config (no caching).
func RequestToken(ctx context.Context, client *http.Client, c *OAuth2Config, env Env) (*Token, error) {
	if c.TokenURL == "" {
		return nil, fmt.Errorf("oauth2: token_url is required")
	}
	f, err := GrantForm(c, env)
	if err != nil {
		return nil, err
	}
	raw, err := PostForm(ctx, client, c.TokenURL, c.clientAuth(), f)
	if err != nil {
		return nil, err
	}
	return ParseToken(raw)
}

// refreshToken exchanges a refresh token using the config's client auth.
func refreshToken(ctx context.Context, client *http.Client, c *OAuth2Config, rt string) (*Token, error) {
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if len(c.Scopes) > 0 {
		f.Set("scope", strings.Join(c.Scopes, " "))
	}
	raw, err := PostForm(ctx, client, c.TokenURL, c.clientAuth(), f)
	if err != nil {
		return nil, err
	}
	t, err := ParseToken(raw)
	if err != nil {
		return nil, err
	}
	if t.RefreshToken == "" {
		t.RefreshToken = rt
	}
	return t, nil
}

// cacheKey hashes the configuration.
func cacheKey(c *OAuth2Config) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func toCached(t *Token) *cachedToken {
	return &cachedToken{AccessToken: t.AccessToken, TokenType: t.TokenType, RefreshToken: t.RefreshToken, Expiry: t.Expiry, Raw: t.Raw}
}

func fromCached(ct *cachedToken) *Token {
	t := &Token{Raw: ct.Raw}
	if ct.Raw != nil {
		if p, err := ParseToken(ct.Raw); err == nil {
			t = p
		}
	}
	t.AccessToken, t.TokenType, t.RefreshToken, t.Expiry = ct.AccessToken, ct.TokenType, ct.RefreshToken, ct.Expiry
	if !t.Expiry.IsZero() {
		t.ExpiresIn = int64(time.Until(t.Expiry).Seconds())
		if t.ExpiresIn < 0 {
			t.ExpiresIn = 0
		}
	}
	return t
}

// TokenSource says where a token returned by OAuth2Token came from.
type TokenSource string

// Token sources.
const (
	SourceCache       TokenSource = "cache"
	SourceRefreshed   TokenSource = "refreshed"
	SourceRequested   TokenSource = "requested"
	SourcePassthrough TokenSource = "access_token"
)

// OAuth2Token returns an access token for the config. With useCache, a
// cached unexpired token is reused, an expired one is refreshed with its
// refresh token (falling back to a new grant), and the result is cached.
func (m *Manager) OAuth2Token(ctx context.Context, c *OAuth2Config, env Env, useCache bool) (*Token, TokenSource, error) {
	if c == nil {
		return nil, "", fmt.Errorf("auth oauth2: the oauth2 object is required")
	}
	if c.GrantName() == "access_token" || (c.AccessToken != "" && c.TokenURL == "") {
		if c.AccessToken == "" {
			return nil, "", fmt.Errorf("auth oauth2: access_token is required for grant access_token")
		}
		return &Token{AccessToken: c.AccessToken, TokenType: c.TokenType}, SourcePassthrough, nil
	}
	if env.TokenClient == nil {
		return nil, "", fmt.Errorf("auth oauth2: token client not configured")
	}
	key := cacheKey(c)
	if useCache {
		m.mu.Lock()
		ct := m.tokens[key]
		m.mu.Unlock()
		if ct != nil {
			t := fromCached(ct)
			if !t.Expired() {
				return t, SourceCache, nil
			}
			if t.RefreshToken != "" && c.TokenURL != "" {
				if nt, err := refreshToken(ctx, env.TokenClient(), c, t.RefreshToken); err == nil {
					m.store(key, nt)
					return nt, SourceRefreshed, nil
				}
			}
			m.mu.Lock()
			delete(m.tokens, key)
			m.mu.Unlock()
		}
	}
	t, err := RequestToken(ctx, env.TokenClient(), c, env)
	if err != nil {
		return nil, "", err
	}
	if c.GrantName() == "refresh_token" && t.RefreshToken == "" {
		t.RefreshToken = c.RefreshToken
	}
	if useCache {
		m.store(key, t)
	}
	return t, SourceRequested, nil
}

func (m *Manager) store(key string, t *Token) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens == nil {
		m.tokens = map[string]*cachedToken{}
	}
	m.tokens[key] = toCached(t)
}

// ForgetToken drops a cached token for the config.
func (m *Manager) ForgetToken(c *OAuth2Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, cacheKey(c))
}

func (m *Manager) oauth2Signer(c *OAuth2Config, env Env) (Signer, error) {
	if c == nil {
		return nil, fmt.Errorf("auth oauth2: the oauth2 object is required")
	}
	if c.GrantName() != "access_token" && c.AccessToken == "" && c.TokenURL == "" {
		return nil, fmt.Errorf("auth oauth2: token_url is required (or pass access_token)")
	}
	return SignerFunc(func(ctx context.Context, r *http.Request) error {
		t, _, err := m.OAuth2Token(ctx, c, env, true)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", t.AuthorizationValue(c.TokenType))
		return nil
	}), nil
}
