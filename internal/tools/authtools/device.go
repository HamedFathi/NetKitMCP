package authtools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const (
	defaultPollWait = 30.0
	maxPollWait     = 300.0
	minInterval     = 0.1
)

type deviceStartIn struct {
	DeviceAuthorizationURL string            `json:"device_authorization_url" jsonschema:"the device authorization endpoint"`
	ClientID               string            `json:"client_id"`
	ClientSecret           string            `json:"client_secret,omitempty" jsonschema:"omit for public clients"`
	Scopes                 []string          `json:"scopes,omitempty"`
	Audience               string            `json:"audience,omitempty"`
	AuthStyle              string            `json:"auth_style,omitempty" jsonschema:"header (Basic, default when a secret is set) or body"`
	ExtraParams            map[string]string `json:"extra_params,omitempty"`
	types.HTTPOptions
}

type deviceStartOut struct {
	DeviceCode              string         `json:"device_code"`
	UserCode                string         `json:"user_code"`
	VerificationURI         string         `json:"verification_uri"`
	VerificationURIComplete string         `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64          `json:"expires_in,omitempty"`
	Interval                int64          `json:"interval"`
	Raw                     map[string]any `json:"raw,omitempty"`
	Next                    string         `json:"next"`
	Warnings                []string       `json:"warnings,omitempty"`
}

type devicePollIn struct {
	TokenURL        string            `json:"token_url"`
	ClientID        string            `json:"client_id"`
	ClientSecret    string            `json:"client_secret,omitempty"`
	DeviceCode      string            `json:"device_code" jsonschema:"device_code from oauth2_device_start"`
	IntervalSeconds float64           `json:"interval_seconds,omitempty" jsonschema:"polling interval from oauth2_device_start (default 5)"`
	MaxWaitSeconds  float64           `json:"max_wait_seconds,omitempty" jsonschema:"how long this call keeps polling before returning authorization_pending (default 30, max 300)"`
	AuthStyle       string            `json:"auth_style,omitempty"`
	ExtraParams     map[string]string `json:"extra_params,omitempty"`
	types.HTTPOptions
}

type devicePollOut struct {
	Status              string  `json:"status" jsonschema:"authorized, authorization_pending, access_denied or expired_token"`
	Description         string  `json:"description,omitempty"`
	NextIntervalSeconds float64 `json:"next_interval_seconds,omitempty"`
	Polls               int     `json:"polls"`
	*tokenOut
	Next string `json:"next,omitempty"`
}

func registerDevice(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "oauth2_device_start", "OAuth2 device flow start",
		"Start the OAuth2 device authorization flow (RFC 8628). Returns user_code and verification_uri for the user to visit, plus "+
			"device_code and interval to pass to oauth2_device_poll.",
		tools.Mutating,
		func(ctx context.Context, req *mcp.CallToolRequest, in deviceStartIn) (any, error) {
			if in.DeviceAuthorizationURL == "" || in.ClientID == "" {
				return nil, fmt.Errorf("device_authorization_url and client_id are required")
			}
			form := url.Values{}
			if len(in.Scopes) > 0 {
				form.Set("scope", strings.Join(in.Scopes, " "))
			}
			if in.Audience != "" {
				form.Set("audience", in.Audience)
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
			raw, err := auth.PostForm(ctx, c.Client, in.DeviceAuthorizationURL, auth.ClientAuth{ClientID: in.ClientID, ClientSecret: in.ClientSecret, Style: in.AuthStyle}, form)
			if err != nil {
				return nil, explain(err)
			}
			out := deviceStartOut{Raw: raw, Warnings: warnings}
			out.DeviceCode, _ = raw["device_code"].(string)
			out.UserCode, _ = raw["user_code"].(string)
			out.VerificationURI, _ = raw["verification_uri"].(string)
			if out.VerificationURI == "" {
				out.VerificationURI, _ = raw["verification_url"].(string) // pre-RFC Google naming
			}
			out.VerificationURIComplete, _ = raw["verification_uri_complete"].(string)
			out.ExpiresIn = intOf(raw["expires_in"])
			out.Interval = intOf(raw["interval"])
			if _, ok := raw["interval"]; !ok {
				out.Interval = 5
			}
			if out.DeviceCode == "" || out.UserCode == "" {
				return nil, fmt.Errorf("device authorization response lacks device_code/user_code")
			}
			out.Next = fmt.Sprintf("Ask the user to open %s and enter code %s, then call oauth2_device_poll with device_code and interval_seconds=%d.",
				out.VerificationURI, out.UserCode, out.Interval)
			if out.VerificationURIComplete != "" {
				out.Next = fmt.Sprintf("Ask the user to open %s (or %s and enter code %s), then call oauth2_device_poll with device_code and interval_seconds=%d.",
					out.VerificationURIComplete, out.VerificationURI, out.UserCode, out.Interval)
			}
			return out, nil
		})

	tools.Add(s, d, "oauth2_device_poll", "OAuth2 device flow poll",
		"Poll the token endpoint for a device flow started with oauth2_device_start. Polls at interval_seconds until the user approves, "+
			"a terminal error occurs, or max_wait_seconds (default 30) elapses. Returns status authorized (with the tokens), "+
			"authorization_pending (call again), access_denied or expired_token.",
		tools.Mutating,
		func(ctx context.Context, req *mcp.CallToolRequest, in devicePollIn) (any, error) {
			if in.TokenURL == "" || in.DeviceCode == "" {
				return nil, fmt.Errorf("token_url and device_code are required")
			}
			interval := in.IntervalSeconds
			if interval <= 0 {
				interval = 5
			}
			interval = max(interval, minInterval)
			wait := in.MaxWaitSeconds
			if wait <= 0 {
				wait = defaultPollWait
			}
			wait = min(wait, maxPollWait)

			c, warnings, err := client(d, in.HTTPOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			deadline := time.Now().Add(time.Duration(wait * float64(time.Second)))
			ctx, cancel := context.WithDeadline(ctx, deadline.Add(c.Timeout))
			defer cancel()

			form := url.Values{"grant_type": {auth.GrantDeviceCode}, "device_code": {in.DeviceCode}}
			for k, v := range in.ExtraParams {
				form.Set(k, v)
			}
			ca := auth.ClientAuth{ClientID: in.ClientID, ClientSecret: in.ClientSecret, Style: in.AuthStyle}
			out := devicePollOut{}
			for {
				out.Polls++
				rctx, rcancel := context.WithTimeout(ctx, c.Timeout)
				raw, err := auth.PostForm(rctx, c.Client, in.TokenURL, ca, form)
				rcancel()
				if err == nil {
					tok, err := auth.ParseToken(raw)
					if err != nil {
						return nil, err
					}
					to := toOut(tok)
					to.Warnings = warnings
					out.Status = "authorized"
					out.tokenOut = &to
					return out, nil
				}
				var te *auth.TokenError
				if !errors.As(err, &te) {
					return nil, err
				}
				switch te.Code {
				case "authorization_pending":
				case "slow_down":
					interval += 5
				case "access_denied", "expired_token":
					out.Status, out.Description = te.Code, te.Description
					if te.Code == "expired_token" {
						out.Next = "The device code expired; start again with oauth2_device_start."
					} else {
						out.Next = "The user denied the request."
					}
					return out, nil
				default:
					return nil, explain(err)
				}
				sleep := time.Duration(interval * float64(time.Second))
				if time.Now().Add(sleep).After(deadline) {
					out.Status = "authorization_pending"
					out.Description = te.Description
					out.NextIntervalSeconds = interval
					out.Next = "The user has not approved yet; call oauth2_device_poll again with the same device_code and interval_seconds=next_interval_seconds."
					return out, nil
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(sleep):
				}
			}
		})
}

func intOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		var n int64
		fmt.Sscan(x, &n)
		return n
	}
	return 0
}
