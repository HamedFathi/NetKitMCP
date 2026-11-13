package authtools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// OOBRedirect is the default out-of-band redirect URI.
const OOBRedirect = "urn:ietf:wg:oauth:2.0:oob"

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// S256 returns the PKCE S256 code challenge of a verifier.
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type authURLIn struct {
	AuthorizationURL string            `json:"authorization_url" jsonschema:"the authorization endpoint"`
	ClientID         string            `json:"client_id"`
	RedirectURI      string            `json:"redirect_uri,omitempty" jsonschema:"registered redirect URI (default urn:ietf:wg:oauth:2.0:oob)"`
	Scopes           []string          `json:"scopes,omitempty"`
	State            string            `json:"state,omitempty" jsonschema:"state value (default: random)"`
	PKCEMethod       string            `json:"pkce_method,omitempty" jsonschema:"S256 (default), plain or none"`
	CodeVerifier     string            `json:"code_verifier,omitempty" jsonschema:"use this verifier instead of generating one (43-128 chars)"`
	Audience         string            `json:"audience,omitempty"`
	Resource         string            `json:"resource,omitempty"`
	ResponseType     string            `json:"response_type,omitempty" jsonschema:"default code"`
	ExtraParams      map[string]string `json:"extra_params,omitempty" jsonschema:"additional query parameters (prompt, login_hint, access_type, ...)"`
}

type authURLOut struct {
	URL                 string `json:"url"`
	State               string `json:"state"`
	CodeVerifier        string `json:"code_verifier,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	RedirectURI         string `json:"redirect_uri"`
	Next                string `json:"next"`
}

type exchangeIn struct {
	TokenURL     string            `json:"token_url"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty" jsonschema:"omit for public clients"`
	Code         string            `json:"code,omitempty" jsonschema:"authorization code (or pass redirect_url)"`
	RedirectURL  string            `json:"redirect_url,omitempty" jsonschema:"the full URL the browser was redirected to; code and state are extracted from it"`
	CodeVerifier string            `json:"code_verifier,omitempty" jsonschema:"PKCE verifier returned by oauth2_auth_url"`
	RedirectURI  string            `json:"redirect_uri,omitempty" jsonschema:"must equal the one used for oauth2_auth_url (default: derived from redirect_url, else urn:ietf:wg:oauth:2.0:oob)"`
	State        string            `json:"state,omitempty" jsonschema:"expected state; checked against the state in redirect_url"`
	AuthStyle    string            `json:"auth_style,omitempty" jsonschema:"header (Basic, default) or body"`
	ExtraParams  map[string]string `json:"extra_params,omitempty"`
	types.HTTPOptions
}

func registerAuthCode(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "oauth2_auth_url", "OAuth2 authorization URL",
		"Step 1 of the OAuth2 authorization-code flow with PKCE (stateless, no callback listener). Builds the authorization URL and "+
			"returns it with state and code_verifier. Ask the user to open the URL, sign in and paste back the code or the full redirect URL, "+
			"then call oauth2_exchange_code with code_verifier and state. redirect_uri defaults to urn:ietf:wg:oauth:2.0:oob.",
		tools.Local,
		func(ctx context.Context, req *mcp.CallToolRequest, in authURLIn) (any, error) {
			u, err := url.Parse(in.AuthorizationURL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return nil, fmt.Errorf("authorization_url must be an absolute http(s) URL")
			}
			if in.ClientID == "" {
				return nil, fmt.Errorf("client_id is required")
			}
			out := authURLOut{RedirectURI: in.RedirectURI, State: in.State}
			if out.RedirectURI == "" {
				out.RedirectURI = OOBRedirect
			}
			if out.State == "" {
				out.State = randomToken(16)
			}
			q := u.Query()
			rt := in.ResponseType
			if rt == "" {
				rt = "code"
			}
			q.Set("response_type", rt)
			q.Set("client_id", in.ClientID)
			q.Set("redirect_uri", out.RedirectURI)
			q.Set("state", out.State)
			if len(in.Scopes) > 0 {
				q.Set("scope", strings.Join(in.Scopes, " "))
				for _, sc := range in.Scopes {
					if sc == "openid" {
						out.Nonce = randomToken(16)
						q.Set("nonce", out.Nonce)
					}
				}
			}
			switch m := strings.ToUpper(in.PKCEMethod); m {
			case "", "S256", "PLAIN":
				v := in.CodeVerifier
				if v == "" {
					v = randomToken(48) // 64 chars
				}
				if len(v) < 43 || len(v) > 128 {
					return nil, fmt.Errorf("code_verifier must be 43-128 characters")
				}
				out.CodeVerifier = v
				if m == "PLAIN" {
					out.CodeChallenge, out.CodeChallengeMethod = v, "plain"
				} else {
					out.CodeChallenge, out.CodeChallengeMethod = S256(v), "S256"
				}
				q.Set("code_challenge", out.CodeChallenge)
				q.Set("code_challenge_method", out.CodeChallengeMethod)
			case "NONE":
			default:
				return nil, fmt.Errorf("pkce_method must be S256, plain or none")
			}
			if in.Audience != "" {
				q.Set("audience", in.Audience)
			}
			if in.Resource != "" {
				q.Set("resource", in.Resource)
			}
			for k, v := range in.ExtraParams {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
			out.URL = u.String()
			out.Next = "Ask the user to open url and approve access, then call oauth2_exchange_code with the code (or the full redirect URL), code_verifier, state and the same redirect_uri."
			return out, nil
		})

	tools.Add(s, d, "oauth2_exchange_code", "OAuth2 exchange code",
		"Step 2 of the OAuth2 authorization-code flow: exchange the authorization code (or a pasted redirect URL containing code and state) "+
			"plus the PKCE code_verifier from oauth2_auth_url for tokens at token_url. Pass state to have it checked against the redirect URL. "+
			"redirect_uri must match step 1.",
		tools.Mutating,
		func(ctx context.Context, req *mcp.CallToolRequest, in exchangeIn) (any, error) {
			if in.TokenURL == "" {
				return nil, fmt.Errorf("token_url is required")
			}
			code := strings.TrimSpace(in.Code)
			redirectURI := in.RedirectURI
			if in.RedirectURL != "" {
				ru, err := url.Parse(strings.TrimSpace(in.RedirectURL))
				if err != nil {
					return nil, fmt.Errorf("redirect_url: %v", err)
				}
				q := ru.Query()
				if ru.Fragment != "" && q.Get("code") == "" && q.Get("error") == "" {
					if fq, err := url.ParseQuery(ru.Fragment); err == nil {
						q = fq
					}
				}
				if e := q.Get("error"); e != "" {
					return nil, fmt.Errorf("authorization failed: %s %s", e, q.Get("error_description"))
				}
				if in.State != "" && q.Get("state") != in.State {
					return nil, fmt.Errorf("state mismatch: expected %q, redirect has %q (possible CSRF or a stale URL; restart with oauth2_auth_url)", in.State, q.Get("state"))
				}
				if code == "" {
					code = q.Get("code")
				}
				if redirectURI == "" && ru.Scheme != "" && ru.Host != "" {
					base := *ru
					base.RawQuery, base.Fragment = "", ""
					redirectURI = base.String()
				}
			}
			if code == "" {
				return nil, fmt.Errorf("code is required (or pass redirect_url containing ?code=...)")
			}
			if redirectURI == "" {
				redirectURI = OOBRedirect
			}
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
			if in.CodeVerifier != "" {
				form.Set("code_verifier", in.CodeVerifier)
			}
			for k, v := range in.ExtraParams {
				form.Set(k, v)
			}
			c, warnings, err := client(d, in.HTTPOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			ctx, cancel := withTimeout(ctx, c)
			defer cancel()
			raw, err := auth.PostForm(ctx, c.Client, in.TokenURL, auth.ClientAuth{ClientID: in.ClientID, ClientSecret: in.ClientSecret, Style: in.AuthStyle}, form)
			if err != nil {
				return nil, explain(err)
			}
			tok, err := auth.ParseToken(raw)
			if err != nil {
				return nil, err
			}
			out := toOut(tok)
			out.Source = "requested"
			out.Warnings = warnings
			return out, nil
		})
}
