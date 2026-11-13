package auth

import (
	"fmt"
	"net/http"
	"time"
)

// cachedToken is an OAuth2 token cache entry.
type cachedToken struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
	Raw          map[string]any
}

// extSigner returns signers for jwt, oauth2, oauth1, aws_sigv4, hawk,
// akamai_edgegrid and asap.
func (m *Manager) extSigner(c *Config, env Env) (Signer, error) {
	switch c.Kind() {
	case "jwt":
		return jwtSigner(c.JWT, env)
	case "asap":
		return asapSigner(c.ASAP, env)
	case "oauth2":
		return m.oauth2Signer(c.OAuth2, env)
	case "oauth1":
		return newOAuth1Signer(c.OAuth1, env)
	case "aws_sigv4":
		return newSigV4Signer(c.AWS)
	case "hawk":
		return newHawkSigner(c.Hawk)
	case "akamai_edgegrid":
		return newEdgeGridSigner(c.EdgeGrid)
	}
	return nil, fmt.Errorf("auth type %q is not supported (see the type field for valid values)", c.Type)
}

// challengeTransport returns round trippers for digest, ntlm and negotiate.
func (m *Manager) challengeTransport(base http.RoundTripper, c *Config, env Env) (http.RoundTripper, error) {
	switch c.Kind() {
	case "digest":
		return digestTransport(base, c)
	case "ntlm":
		return newNTLMTransport(base, c)
	case "negotiate":
		return newNegotiateTransport(base, c, env)
	}
	return nil, fmt.Errorf("auth type %q is not supported", c.Type)
}
