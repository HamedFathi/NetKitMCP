package auth

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/icholy/digest"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// digestTransport answers RFC 7616 / 2617 Digest challenges (MD5, SHA-256,
// SHA-512-256, qop auth and auth-int). Bodies without GetBody are buffered
// so the authenticated retry can resend them.
func digestTransport(base http.RoundTripper, c *Config) (http.RoundTripper, error) {
	if c.Username == "" {
		return nil, fmt.Errorf("auth digest: username is required")
	}
	return &digest.Transport{Username: c.Username, Password: c.Password, Transport: base}, nil
}

// ntlmTransport performs the NTLM (or Negotiate-NTLM) handshake. The
// underlying transport must keep the connection alive between the
// handshake legs (http.Transport does); bodies are rewound or buffered.
type ntlmTransport struct {
	neg  ntlmssp.Negotiator
	user string
	pass string
}

func newNTLMTransport(base http.RoundTripper, c *Config) (http.RoundTripper, error) {
	if c.Username == "" {
		return nil, fmt.Errorf("auth ntlm: username is required")
	}
	user := c.Username
	if c.Domain != "" && !strings.ContainsAny(user, `\@`) {
		user = c.Domain + `\` + user
	}
	return &ntlmTransport{neg: ntlmssp.Negotiator{RoundTripper: base}, user: user, pass: c.Password}, nil
}

func (t *ntlmTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Body = req.Body
	r.SetBasicAuth(t.user, t.pass)
	return t.neg.RoundTrip(r)
}

// negotiateTransport adds a Kerberos SPNEGO token to every request.
type negotiateTransport struct {
	base http.RoundTripper
	cl   *client.Client
	spn  string
}

// krb5Config builds the Kerberos configuration from krb5_conf (inline or
// file) or from realm/kdc.
func krb5Config(k *KerberosConfig, env Env) (*krbconfig.Config, error) {
	if k.Krb5Conf != "" {
		v := k.Krb5Conf
		if !strings.Contains(v, "[") && !strings.Contains(v, "\n") {
			if env.Files == nil {
				return nil, fmt.Errorf("krb5_conf file access not configured")
			}
			b, err := env.Files.ReadSmall(v, 1<<20)
			if err != nil {
				return nil, fmt.Errorf("krb5_conf: %w", err)
			}
			v = string(b)
		}
		cfg, err := krbconfig.NewFromString(v)
		if err != nil {
			return nil, fmt.Errorf("krb5_conf: %w", err)
		}
		if k.Realm != "" && cfg.LibDefaults.DefaultRealm == "" {
			cfg.LibDefaults.DefaultRealm = k.Realm
		}
		return cfg, nil
	}
	if k.Realm == "" || k.KDC == "" {
		return nil, fmt.Errorf("realm and kdc (or krb5_conf) are required")
	}
	kdc := k.KDC
	if _, _, err := net.SplitHostPort(kdc); err != nil {
		kdc = net.JoinHostPort(kdc, "88")
	}
	conf := fmt.Sprintf("[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n udp_preference_limit = 1\n\n[realms]\n %s = {\n  kdc = %s\n }\n",
		k.Realm, k.Realm, kdc)
	return krbconfig.NewFromString(conf)
}

func newNegotiateTransport(base http.RoundTripper, c *Config, env Env) (http.RoundTripper, error) {
	k := c.Kerberos
	if k == nil {
		k = &KerberosConfig{}
	}
	cfg, err := krb5Config(k, env)
	if err != nil {
		return nil, fmt.Errorf("auth negotiate: %w", err)
	}
	realm := k.Realm
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}
	user := c.Username
	if u, r, ok := strings.Cut(user, "@"); ok {
		user = u
		if realm == "" {
			realm = r
		}
	}
	if user == "" || realm == "" {
		return nil, fmt.Errorf("auth negotiate: username and kerberos.realm are required")
	}
	if env.CheckAddress != nil {
		for _, rc := range cfg.Realms {
			if !strings.EqualFold(rc.Realm, realm) {
				continue
			}
			for _, kdc := range rc.KDC {
				if _, _, err := net.SplitHostPort(kdc); err != nil {
					kdc = net.JoinHostPort(kdc, "88")
				}
				if err := env.CheckAddress(kdc); err != nil {
					return nil, fmt.Errorf("auth negotiate: KDC %s: %w", kdc, err)
				}
			}
		}
	}
	settings := []func(*client.Settings){client.DisablePAFXFAST(k.DisablePAFX)}
	var cl *client.Client
	switch {
	case k.Keytab != "":
		kb, err := loadKeytab(k.Keytab, env)
		if err != nil {
			return nil, fmt.Errorf("auth negotiate keytab: %w", err)
		}
		cl = client.NewWithKeytab(user, realm, kb, cfg, settings...)
	case c.Password != "":
		cl = client.NewWithPassword(user, realm, c.Password, cfg, settings...)
	default:
		return nil, fmt.Errorf("auth negotiate: password or kerberos.keytab is required")
	}
	return &negotiateTransport{base: base, cl: cl, spn: k.SPN}, nil
}

func loadKeytab(v string, env Env) (*keytab.Keytab, error) {
	var b []byte
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return nil, err
		}
		b = d
	} else {
		if env.Files == nil {
			return nil, fmt.Errorf("file access not configured")
		}
		d, err := env.Files.ReadSmall(v, 1<<20)
		if err != nil {
			return nil, err
		}
		b = d
	}
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, err
	}
	return kt, nil
}

func (t *negotiateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Body = req.Body
	spn := t.spn
	if spn == "" {
		spn = "HTTP/" + strings.ToLower(req.URL.Hostname())
	}
	if err := spnego.SetSPNEGOHeader(t.cl, r, spn); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("auth negotiate: %w", err)
	}
	return t.base.RoundTrip(r)
}
