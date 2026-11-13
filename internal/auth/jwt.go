package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// now is the clock used by signers (overridable in tests).
var now = time.Now

// SignJWT builds and signs a JWT from cfg. It is exported so other packages
// (and the oauth2 jwt_bearer grant) can mint assertions.
func SignJWT(cfg *JWTConfig, env Env) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("jwt settings are required")
	}
	if cfg.Token != "" {
		return cfg.Token, nil
	}
	alg := cfg.Algorithm
	if alg == "" {
		alg = "HS256"
	}
	claims := jwt.MapClaims{}
	t := now()
	exp := cfg.ExpiresIn
	if exp <= 0 {
		exp = 300
	}
	claims["iat"] = t.Unix()
	claims["exp"] = t.Add(time.Duration(exp * float64(time.Second))).Unix()
	if cfg.Issuer != "" {
		claims["iss"] = cfg.Issuer
	}
	if cfg.Subject != "" {
		claims["sub"] = cfg.Subject
	}
	switch len(cfg.Audience) {
	case 0:
	case 1:
		claims["aud"] = cfg.Audience[0]
	default:
		claims["aud"] = cfg.Audience
	}
	for k, v := range cfg.Claims {
		claims[k] = v
	}
	var secret []byte
	if strings.HasPrefix(strings.ToUpper(alg), "HS") {
		secret = []byte(cfg.Secret)
		if cfg.SecretB64 {
			b, err := decodeB64(cfg.Secret)
			if err != nil {
				return "", fmt.Errorf("jwt secret_base64: %w", err)
			}
			secret = b
		}
		if len(secret) == 0 {
			return "", fmt.Errorf("jwt %s: secret is required", alg)
		}
	}
	return signToken(alg, cfg.KeyID, cfg.Key, secret, claims, cfg.Headers, env)
}

// signToken signs claims with the algorithm. keyRef is a PEM or file path
// for asymmetric algorithms; secret is the HMAC key.
func signToken(alg, kid, keyRef string, secret []byte, claims jwt.MapClaims, headers map[string]any, env Env) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unsupported jwt algorithm %q (use HS256/384/512, RS*, ES*, PS* or EdDSA)", alg)
	}
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range headers {
		tok.Header[k] = v
	}
	if kid != "" {
		tok.Header["kid"] = kid
	}
	var key any
	switch {
	case strings.HasPrefix(alg, "HS"):
		key = secret
	default:
		if keyRef == "" {
			return "", fmt.Errorf("jwt %s: private_key is required", alg)
		}
		pemBytes, err := LoadKey(env, keyRef)
		if err != nil {
			return "", fmt.Errorf("jwt private_key: %w", err)
		}
		switch {
		case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
			key, err = jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
		case strings.HasPrefix(alg, "ES"):
			key, err = jwt.ParseECPrivateKeyFromPEM(pemBytes)
		case alg == "EdDSA":
			key, err = jwt.ParseEdPrivateKeyFromPEM(pemBytes)
		default:
			err = fmt.Errorf("unsupported algorithm")
		}
		if err != nil {
			return "", fmt.Errorf("jwt %s private_key: %w", alg, err)
		}
	}
	s, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("jwt sign: %w", err)
	}
	return s, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

// jwtSigner places a freshly signed (or pre-built) JWT on each request.
func jwtSigner(cfg *JWTConfig, env Env) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth jwt: the jwt object is required")
	}
	// Validate eagerly so configuration errors surface before sending.
	if _, err := SignJWT(cfg, env); err != nil {
		return nil, fmt.Errorf("auth jwt: %w", err)
	}
	return SignerFunc(func(_ context.Context, r *http.Request) error {
		tok, err := SignJWT(cfg, env)
		if err != nil {
			return err
		}
		if cfg.QueryKey != "" {
			q := r.URL.Query()
			q.Set(cfg.QueryKey, tok)
			r.URL.RawQuery = q.Encode()
			return nil
		}
		header := cfg.Header
		if header == "" {
			header = "Authorization"
		}
		prefix := cfg.Prefix
		if prefix == "" && strings.EqualFold(header, "Authorization") {
			prefix = "Bearer"
		}
		r.Header.Set(header, strings.TrimSpace(prefix+" "+tok))
		return nil
	}), nil
}

// asapToken mints an ASAP token (Atlassian S2S Authentication Protocol).
func asapToken(cfg *ASAPConfig, env Env) (string, error) {
	if cfg.Issuer == "" || cfg.KeyID == "" || len(cfg.Audience) == 0 || cfg.PrivateKey == "" {
		return "", fmt.Errorf("iss, kid, aud and private_key are required")
	}
	alg := cfg.Algorithm
	if alg == "" {
		alg = "RS256"
	}
	if strings.HasPrefix(alg, "HS") {
		return "", fmt.Errorf("ASAP requires an asymmetric algorithm (RS256 default)")
	}
	exp := cfg.ExpiresIn
	if exp <= 0 {
		exp = 60
	}
	if exp > 3600 {
		exp = 3600
	}
	t := now()
	claims := jwt.MapClaims{}
	for k, v := range cfg.Claims {
		claims[k] = v
	}
	claims["iss"] = cfg.Issuer
	sub := cfg.Subject
	if sub == "" {
		sub = cfg.Issuer
	}
	claims["sub"] = sub
	if len(cfg.Audience) == 1 {
		claims["aud"] = cfg.Audience[0]
	} else {
		claims["aud"] = cfg.Audience
	}
	claims["jti"] = randomURLSafe(16)
	claims["iat"] = t.Unix()
	claims["nbf"] = t.Unix()
	claims["exp"] = t.Add(time.Duration(exp * float64(time.Second))).Unix()
	return signToken(alg, cfg.KeyID, cfg.PrivateKey, nil, claims, nil, env)
}

func asapSigner(cfg *ASAPConfig, env Env) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth asap: the asap object is required")
	}
	if _, err := asapToken(cfg, env); err != nil {
		return nil, fmt.Errorf("auth asap: %w", err)
	}
	return SignerFunc(func(_ context.Context, r *http.Request) error {
		tok, err := asapToken(cfg, env)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}), nil
}
