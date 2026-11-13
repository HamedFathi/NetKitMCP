// Package auth turns the shared `auth` argument object into HTTP round
// trippers, request signers, gRPC credentials and connection credentials.
package auth

// Config is the shared auth object. Type is the discriminator; only the
// fields relevant to that type are read.
type Config struct {
	Type string `json:"type" jsonschema:"none|basic|bearer|api_key|digest|oauth1|oauth2|aws_sigv4|jwt|hawk|ntlm|negotiate|akamai_edgegrid|asap|mtls|custom_header|cookie|ws_security|ssh_key|ssh_password"`

	// basic, digest, ntlm, negotiate, ws_security, ssh_password, broker auth.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty" jsonschema:"NTLM domain"`

	// bearer
	Token  string `json:"token,omitempty" jsonschema:"bearer token"`
	Prefix string `json:"prefix,omitempty" jsonschema:"bearer scheme prefix (default Bearer)"`

	// api_key
	Key string `json:"key,omitempty" jsonschema:"api_key name (header, query parameter or cookie)"`
	// Value is the api_key value.
	Value string `json:"value,omitempty" jsonschema:"api_key value"`
	In    string `json:"in,omitempty" jsonschema:"api_key location: header (default), query or cookie"`

	// custom_header / cookie
	Headers map[string]string `json:"headers,omitempty" jsonschema:"custom_header: headers to add"`
	Cookies map[string]string `json:"cookies,omitempty" jsonschema:"cookie: cookies to send"`

	OAuth2   *OAuth2Config   `json:"oauth2,omitempty"`
	OAuth1   *OAuth1Config   `json:"oauth1,omitempty"`
	AWS      *AWSConfig      `json:"aws,omitempty"`
	JWT      *JWTConfig      `json:"jwt,omitempty"`
	Hawk     *HawkConfig     `json:"hawk,omitempty"`
	Kerberos *KerberosConfig `json:"kerberos,omitempty"`
	EdgeGrid *EdgeGridConfig `json:"edgegrid,omitempty"`
	ASAP     *ASAPConfig     `json:"asap,omitempty"`
	MTLS     *MTLSConfig     `json:"mtls,omitempty"`
	WSSec    *WSSecConfig    `json:"ws_security,omitempty"`
	SSH      *SSHConfig      `json:"ssh,omitempty"`
}

// OAuth2Config configures oauth2 token acquisition. Access tokens are cached
// in memory keyed by the configuration and refreshed when expired.
type OAuth2Config struct {
	Grant            string            `json:"grant,omitempty" jsonschema:"client_credentials (default)|password|refresh_token|jwt_bearer|token_exchange|access_token"`
	TokenURL         string            `json:"token_url,omitempty"`
	ClientID         string            `json:"client_id,omitempty"`
	ClientSecret     string            `json:"client_secret,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	Audience         string            `json:"audience,omitempty"`
	Resource         string            `json:"resource,omitempty"`
	Username         string            `json:"username,omitempty"`
	Password         string            `json:"password,omitempty"`
	RefreshToken     string            `json:"refresh_token,omitempty"`
	AccessToken      string            `json:"access_token,omitempty" jsonschema:"use an existing access token directly"`
	Assertion        string            `json:"assertion,omitempty" jsonschema:"jwt_bearer: signed assertion (or use jwt to sign one)"`
	SubjectToken     string            `json:"subject_token,omitempty" jsonschema:"token_exchange subject token"`
	SubjectTokenType string            `json:"subject_token_type,omitempty"`
	ActorToken       string            `json:"actor_token,omitempty"`
	ActorTokenType   string            `json:"actor_token_type,omitempty"`
	RequestedType    string            `json:"requested_token_type,omitempty"`
	AuthStyle        string            `json:"auth_style,omitempty" jsonschema:"header (basic, default) or body (client credentials in form body)"`
	ExtraParams      map[string]string `json:"extra_params,omitempty"`
	TokenType        string            `json:"token_type,omitempty" jsonschema:"override token type prefix when applying (default from response, else Bearer)"`
	JWT              *JWTConfig        `json:"jwt,omitempty" jsonschema:"jwt_bearer: sign the assertion with these settings"`
}

// OAuth1Config configures OAuth 1.0a request signing.
type OAuth1Config struct {
	ConsumerKey     string `json:"consumer_key"`
	ConsumerSecret  string `json:"consumer_secret,omitempty"`
	Token           string `json:"token,omitempty"`
	TokenSecret     string `json:"token_secret,omitempty"`
	SignatureMethod string `json:"signature_method,omitempty" jsonschema:"HMAC-SHA1 (default), HMAC-SHA256, RSA-SHA1, RSA-SHA256, PLAINTEXT"`
	PrivateKey      string `json:"private_key,omitempty" jsonschema:"RSA key for RSA-SHA*: inline PEM or file path"`
	Realm           string `json:"realm,omitempty"`
	Callback        string `json:"callback,omitempty"`
	Verifier        string `json:"verifier,omitempty"`
	BodyHash        bool   `json:"body_hash,omitempty" jsonschema:"include oauth_body_hash for non-form bodies"`
	InQuery         bool   `json:"in_query,omitempty" jsonschema:"send oauth params in the query string instead of the Authorization header"`
	Nonce           string `json:"nonce,omitempty" jsonschema:"fixed nonce (testing only)"`
	Timestamp       int64  `json:"timestamp,omitempty" jsonschema:"fixed timestamp (testing only)"`
}

// AWSConfig configures AWS Signature Version 4.
type AWSConfig struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	Region          string `json:"region"`
	Service         string `json:"service"`
	UnsignedPayload bool   `json:"unsigned_payload,omitempty" jsonschema:"use UNSIGNED-PAYLOAD (required for streamed bodies of unknown hash)"`
	Timestamp       string `json:"timestamp,omitempty" jsonschema:"fixed signing time, RFC 3339 or 20060102T150405Z (testing only)"`
}

// JWTConfig configures JWT creation (for the jwt auth type, ASAP and
// oauth2 jwt_bearer assertions).
type JWTConfig struct {
	Algorithm string         `json:"algorithm,omitempty" jsonschema:"HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA (default HS256)"`
	Secret    string         `json:"secret,omitempty" jsonschema:"HMAC secret"`
	SecretB64 bool           `json:"secret_base64,omitempty" jsonschema:"secret is base64 encoded"`
	Key       string         `json:"private_key,omitempty" jsonschema:"private key for RS/ES/PS/EdDSA: inline PEM or file path"`
	KeyID     string         `json:"kid,omitempty"`
	Issuer    string         `json:"iss,omitempty"`
	Subject   string         `json:"sub,omitempty"`
	Audience  []string       `json:"aud,omitempty"`
	ExpiresIn float64        `json:"expires_in_seconds,omitempty" jsonschema:"lifetime (default 300)"`
	Claims    map[string]any `json:"claims,omitempty" jsonschema:"extra claims"`
	Headers   map[string]any `json:"headers,omitempty" jsonschema:"extra JOSE headers"`
	Header    string         `json:"header,omitempty" jsonschema:"HTTP header to put the token in (default Authorization)"`
	Prefix    string         `json:"prefix,omitempty" jsonschema:"prefix for the header value (default Bearer)"`
	QueryKey  string         `json:"query_key,omitempty" jsonschema:"send the token as this query parameter instead of a header"`
	Token     string         `json:"token,omitempty" jsonschema:"use this pre-built JWT instead of signing one"`
}

// HawkConfig configures Hawk authentication.
type HawkConfig struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Algorithm string `json:"algorithm,omitempty" jsonschema:"sha256 (default) or sha1"`
	Ext       string `json:"ext,omitempty"`
	App       string `json:"app,omitempty"`
	Dlg       string `json:"dlg,omitempty"`
	Payload   bool   `json:"include_payload_hash,omitempty"`
	Nonce     string `json:"nonce,omitempty" jsonschema:"fixed nonce (testing only)"`
	Timestamp int64  `json:"timestamp,omitempty" jsonschema:"fixed timestamp (testing only)"`
}

// KerberosConfig configures Negotiate (Kerberos/SPNEGO).
type KerberosConfig struct {
	Realm       string `json:"realm"`
	KDC         string `json:"kdc,omitempty" jsonschema:"KDC host:port (default from krb5.conf)"`
	Krb5Conf    string `json:"krb5_conf,omitempty" jsonschema:"krb5.conf contents or file path"`
	Keytab      string `json:"keytab,omitempty" jsonschema:"keytab file path (alternative to password)"`
	SPN         string `json:"spn,omitempty" jsonschema:"service principal (default HTTP/<host>)"`
	DisablePAFX bool   `json:"disable_pafx_fast,omitempty"`
}

// EdgeGridConfig configures Akamai EdgeGrid signing.
type EdgeGridConfig struct {
	ClientToken   string   `json:"client_token"`
	ClientSecret  string   `json:"client_secret"`
	AccessToken   string   `json:"access_token"`
	MaxBody       int      `json:"max_body,omitempty" jsonschema:"bytes of body hashed (default 131072)"`
	HeadersToSign []string `json:"headers_to_sign,omitempty"`
	Nonce         string   `json:"nonce,omitempty" jsonschema:"fixed nonce (testing only)"`
	Timestamp     string   `json:"timestamp,omitempty" jsonschema:"fixed timestamp yyyyMMddTHH:mm:ss+0000 (testing only)"`
}

// ASAPConfig configures Atlassian S2S Authentication Protocol tokens.
type ASAPConfig struct {
	Issuer     string         `json:"iss"`
	KeyID      string         `json:"kid"`
	PrivateKey string         `json:"private_key" jsonschema:"RSA/EC private key: inline PEM or file path"`
	Audience   []string       `json:"aud"`
	Subject    string         `json:"sub,omitempty"`
	Algorithm  string         `json:"algorithm,omitempty" jsonschema:"RS256 (default)"`
	ExpiresIn  float64        `json:"expires_in_seconds,omitempty" jsonschema:"lifetime (default 60, max 3600)"`
	Claims     map[string]any `json:"claims,omitempty"`
}

// MTLSConfig supplies a client certificate (the type "mtls" is otherwise a
// no-op that relies on client_cert/client_key in the TLS options).
type MTLSConfig struct {
	ClientCert string `json:"client_cert" jsonschema:"inline PEM or file path"`
	ClientKey  string `json:"client_key" jsonschema:"inline PEM or file path"`
}

// WSSecConfig configures SOAP WS-Security UsernameToken and Timestamp.
type WSSecConfig struct {
	PasswordType   string  `json:"password_type,omitempty" jsonschema:"text (default) or digest"`
	Timestamp      bool    `json:"timestamp,omitempty" jsonschema:"add a wsu:Timestamp"`
	TTLSeconds     float64 `json:"ttl_seconds,omitempty" jsonschema:"timestamp lifetime (default 300)"`
	MustUnderstand bool    `json:"must_understand,omitempty"`
}

// SSHConfig configures SSH authentication and host-key verification.
type SSHConfig struct {
	PrivateKey            string `json:"private_key,omitempty" jsonschema:"private key: inline PEM/OpenSSH or file path"`
	Passphrase            string `json:"passphrase,omitempty"`
	KnownHosts            string `json:"known_hosts,omitempty" jsonschema:"known_hosts file path or inline contents"`
	HostKeyFingerprint    string `json:"host_key_fingerprint,omitempty" jsonschema:"pinned host key, e.g. SHA256:base64..."`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_host_key,omitempty" jsonschema:"skip host key verification (flagged in the result)"`
}

// Kind returns the normalised auth type.
func (c *Config) Kind() string {
	if c == nil || c.Type == "" {
		return "none"
	}
	return c.Type
}
