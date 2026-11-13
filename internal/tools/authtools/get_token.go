package authtools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type getTokenIn struct {
	auth.OAuth2Config
	UseCache bool `json:"use_cache,omitempty" jsonschema:"reuse a cached unexpired token for the same settings (refreshing it when expired) and cache the result"`
	types.HTTPOptions
}

func registerGetToken(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "oauth2_get_token", "OAuth2 get token",
		"Request an OAuth2 access token from token_url. Grants: client_credentials (default), password (username/password), "+
			"refresh_token, jwt_bearer (assertion, or sign one with jwt), token_exchange (RFC 8693: subject_token, actor_token, requested_token_type). "+
			"Client credentials go in a Basic header (auth_style=header, default) or the form body (auth_style=body). "+
			"Returns access_token, token_type, expires_in/expiry, refresh_token, scope, id_token and the raw response. "+
			"Other tools can also fetch tokens themselves with auth {type:\"oauth2\", oauth2:{...}}.",
		tools.Mutating,
		func(ctx context.Context, req *mcp.CallToolRequest, in getTokenIn) (any, error) {
			if in.TokenURL == "" {
				return nil, fmt.Errorf("token_url is required")
			}
			if in.GrantName() == "access_token" {
				return nil, fmt.Errorf("grant access_token does not request a token; choose client_credentials, password, refresh_token, jwt_bearer or token_exchange")
			}
			c, warnings, err := client(d, in.HTTPOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			ctx, cancel := withTimeout(ctx, c)
			defer cancel()
			cfg := in.OAuth2Config
			tok, src, err := d.Auth.OAuth2Token(ctx, &cfg, env(d, c.Client), in.UseCache)
			if err != nil {
				return nil, explain(err)
			}
			out := toOut(tok)
			out.Source = string(src)
			out.Warnings = warnings
			return out, nil
		})
}
