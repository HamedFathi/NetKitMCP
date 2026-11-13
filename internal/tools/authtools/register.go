package authtools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupAuth, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerGetToken(s, d)
	registerAuthCode(s, d)
	registerDevice(s, d)
}

// tokenOut is the shape returned for any issued token.
type tokenOut struct {
	Status          string         `json:"status,omitempty"`
	AccessToken     string         `json:"access_token"`
	TokenType       string         `json:"token_type,omitempty"`
	ExpiresIn       int64          `json:"expires_in,omitempty"`
	Expiry          string         `json:"expiry,omitempty"`
	RefreshToken    string         `json:"refresh_token,omitempty"`
	Scope           string         `json:"scope,omitempty"`
	IDToken         string         `json:"id_token,omitempty"`
	IssuedTokenType string         `json:"issued_token_type,omitempty"`
	Source          string         `json:"source,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
	Usage           string         `json:"usage,omitempty"`
	Warnings        []string       `json:"warnings,omitempty"`
}

func toOut(t *auth.Token) tokenOut {
	o := tokenOut{
		AccessToken: t.AccessToken, TokenType: t.TokenType, ExpiresIn: t.ExpiresIn,
		RefreshToken: t.RefreshToken, Scope: t.Scope, IDToken: t.IDToken,
		IssuedTokenType: t.IssuedTokenType, Raw: t.Raw,
		Usage: `pass {"type":"bearer","token":"<access_token>"} as the auth argument of other tools`,
	}
	if !t.Expiry.IsZero() {
		o.Expiry = t.Expiry.UTC().Format(time.RFC3339)
	}
	return o
}

// client builds a guarded HTTP client (no auth) for token endpoints.
func client(d *tools.Deps, opts types.HTTPOptions) (*httpx.Client, []string, error) {
	c, err := d.NewHTTPClient(opts, nil)
	if err != nil {
		return nil, nil, err
	}
	var warnings []string
	if c.Insecure {
		warnings = append(warnings, "insecure_skip_verify=true: the server certificate was not verified")
	}
	return c, warnings, nil
}

// env returns an auth environment whose token client is c.
func env(d *tools.Deps, c *http.Client) auth.Env {
	return auth.Env{Files: d.Files, TokenClient: func() *http.Client { return c }}
}

// explain turns endpoint errors into actionable messages.
func explain(err error) error {
	var te *auth.TokenError
	if errors.As(err, &te) {
		switch te.Code {
		case "invalid_client":
			return fmt.Errorf("%w; check client_id/client_secret or try auth_style=body", err)
		case "invalid_grant":
			return fmt.Errorf("%w; the code, refresh token or credentials were rejected (codes are single-use and expire quickly)", err)
		case "invalid_scope":
			return fmt.Errorf("%w; adjust scopes", err)
		}
	}
	return err
}

// withTimeout bounds a call by the client's timeout.
func withTimeout(ctx context.Context, c *httpx.Client) (context.Context, context.CancelFunc) {
	return c.Context(ctx)
}
