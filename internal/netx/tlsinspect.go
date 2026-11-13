package netx

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// TLS versions by name.
var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13,
	"tls1.0": tls.VersionTLS10, "tls1.1": tls.VersionTLS11, "tls1.2": tls.VersionTLS12, "tls1.3": tls.VersionTLS13,
	"tls10": tls.VersionTLS10, "tls11": tls.VersionTLS11, "tls12": tls.VersionTLS12, "tls13": tls.VersionTLS13,
}

// ParseTLSVersion parses "1.2", "TLS1.3", ... ("" = 0).
func ParseTLSVersion(s string) (uint16, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0, nil
	}
	if v, ok := tlsVersions[s]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unknown TLS version %q (use 1.0, 1.1, 1.2 or 1.3)", s)
}

// InspectRequest describes a TLS inspection.
type InspectRequest struct {
	Addr       string      // host:port
	Dial       DialFunc    // guarded dialer (required)
	Base       *tls.Config // client certs, RootCAs (nil RootCAs = system roots)
	ServerName string      // SNI and the name verified against the certificate ("" = none)
	ALPN       []string
	MinVersion uint16
	MaxVersion uint16
	StartTLS   string // "", smtp, imap, pop3, ftp
	Probe      bool   // probe TLS 1.0-1.3 support
	IncludePEM bool
}

// CertInfo describes one certificate.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	CommonName         string   `json:"common_name,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	SerialNumber       string   `json:"serial_number"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysUntilExpiry    int      `json:"days_until_expiry"`
	Expired            bool     `json:"expired"`
	NotYetValid        bool     `json:"not_yet_valid,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	PublicKeySize      int      `json:"public_key_bits,omitempty"`
	SHA256Fingerprint  string   `json:"sha256_fingerprint"`
	IsCA               bool     `json:"is_ca"`
	SelfSigned         bool     `json:"self_signed"`
	KeyUsage           []string `json:"key_usage,omitempty"`
	ExtKeyUsage        []string `json:"ext_key_usage,omitempty"`
	OCSPServers        []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL     []string `json:"issuing_certificate_urls,omitempty"`
	PEM                string   `json:"pem,omitempty"`
}

// Verification reports certificate validation done after the handshake.
type Verification struct {
	Trusted        bool       `json:"trusted"`
	ChainValid     bool       `json:"chain_valid"`
	ChainError     string     `json:"chain_error,omitempty"`
	HostnameValid  *bool      `json:"hostname_valid,omitempty"`
	HostnameError  string     `json:"hostname_error,omitempty"`
	VerifiedName   string     `json:"verified_name,omitempty"`
	RootSource     string     `json:"roots"`
	VerifiedChains [][]string `json:"verified_chains,omitempty"`
}

// VersionProbe is the outcome of a single-version handshake.
type VersionProbe struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	Cipher    string `json:"cipher,omitempty"`
	Error     string `json:"error,omitempty"`
}

// InspectResult is the outcome of a TLS inspection.
type InspectResult struct {
	Address           string         `json:"address"`
	RemoteAddr        string         `json:"remote_addr"`
	ServerName        string         `json:"server_name,omitempty"`
	StartTLS          string         `json:"starttls,omitempty"`
	Version           string         `json:"version"`
	Cipher            string         `json:"cipher"`
	ALPN              string         `json:"alpn,omitempty"`
	CurveID           string         `json:"key_exchange,omitempty"`
	DidResume         bool           `json:"did_resume,omitempty"`
	OCSPStapled       bool           `json:"ocsp_stapled"`
	SCTCount          int            `json:"sct_count"`
	ECHAccepted       bool           `json:"ech_accepted,omitempty"`
	Chain             []CertInfo     `json:"chain"`
	Verification      Verification   `json:"verification"`
	SupportedVersions []VersionProbe `json:"supported_versions,omitempty"`
	TimingMS          struct {
		Connect   float64 `json:"connect"`
		StartTLS  float64 `json:"starttls,omitempty"`
		Handshake float64 `json:"handshake"`
		Total     float64 `json:"total"`
	} `json:"timing_ms"`
	Warnings []string `json:"warnings,omitempty"`
}

// Inspect connects, handshakes without verification, then verifies the
// presented chain and hostname separately so failures are reported rather
// than aborting the inspection.
func Inspect(ctx context.Context, r InspectRequest) (*InspectResult, error) {
	if r.Dial == nil {
		return nil, errors.New("netx: no dialer")
	}
	start := time.Now()
	res := &InspectResult{Address: r.Addr, ServerName: r.ServerName, StartTLS: r.StartTLS, Chain: []CertInfo{}}
	cfg := handshakeConfig(r, r.MinVersion, r.MaxVersion)
	cs, conn, timing, err := handshake(ctx, r, cfg)
	if err != nil {
		return nil, err
	}
	conn.Close()
	res.RemoteAddr = timing.remote
	res.TimingMS.Connect = timing.connect
	res.TimingMS.StartTLS = timing.starttls
	res.TimingMS.Handshake = timing.handshake
	res.Version = tls.VersionName(cs.Version)
	res.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	res.ALPN = cs.NegotiatedProtocol
	if cs.CurveID != 0 {
		res.CurveID = cs.CurveID.String()
	}
	res.DidResume = cs.DidResume
	res.OCSPStapled = len(cs.OCSPResponse) > 0
	res.SCTCount = len(cs.SignedCertificateTimestamps)
	res.ECHAccepted = cs.ECHAccepted
	now := time.Now()
	for _, c := range cs.PeerCertificates {
		res.Chain = append(res.Chain, DescribeCert(c, now, r.IncludePEM))
	}
	res.Verification = Verify(cs.PeerCertificates, r.Base, r.ServerName, now)
	if len(r.ALPN) > 0 && cs.NegotiatedProtocol == "" {
		res.Warnings = append(res.Warnings, "server did not select any of the offered ALPN protocols")
	}
	if r.Probe {
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
			p := VersionProbe{Version: tls.VersionName(v)}
			pcs, pconn, _, err := handshake(ctx, r, handshakeConfig(r, v, v))
			if err != nil {
				p.Error = shortErr(err)
			} else {
				pconn.Close()
				p.Supported = true
				p.Cipher = tls.CipherSuiteName(pcs.CipherSuite)
			}
			res.SupportedVersions = append(res.SupportedVersions, p)
		}
		res.Warnings = append(res.Warnings, "TLS 1.0/1.1 probes use Go's client cipher suites; a server that only offers legacy suites Go no longer implements will show as unsupported")
	}
	res.TimingMS.Total = MS(time.Since(start))
	return res, nil
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.HasPrefix(s, "TLS handshake") {
		return s[i+2:]
	}
	return s
}

func handshakeConfig(r InspectRequest, minV, maxV uint16) *tls.Config {
	var cfg *tls.Config
	if r.Base != nil {
		cfg = r.Base.Clone()
	} else {
		cfg = &tls.Config{}
	}
	cfg.InsecureSkipVerify = true //nolint:gosec // verification is done explicitly afterwards
	cfg.ServerName = r.ServerName
	cfg.NextProtos = r.ALPN
	cfg.MinVersion = tls.VersionTLS10
	if minV != 0 {
		cfg.MinVersion = minV
	}
	cfg.MaxVersion = maxV
	if minV == tls.VersionTLS10 || minV == tls.VersionTLS11 {
		// Offer every suite Go implements, including legacy ones.
		var ids []uint16
		for _, s := range tls.CipherSuites() {
			ids = append(ids, s.ID)
		}
		for _, s := range tls.InsecureCipherSuites() {
			ids = append(ids, s.ID)
		}
		cfg.CipherSuites = ids
	}
	return cfg
}

type hsTiming struct {
	connect, starttls, handshake float64
	remote                       string
}

func handshake(ctx context.Context, r InspectRequest, cfg *tls.Config) (*tls.ConnectionState, net.Conn, hsTiming, error) {
	var tm hsTiming
	t0 := time.Now()
	raw, err := r.Dial(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, nil, tm, err
	}
	tm.connect = MS(time.Since(t0))
	tm.remote = raw.RemoteAddr().String()
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()) })
	defer stop()
	if r.StartTLS != "" {
		t1 := time.Now()
		if err := StartTLS(raw, r.StartTLS); err != nil {
			raw.Close()
			return nil, nil, tm, err
		}
		tm.starttls = MS(time.Since(t1))
	}
	t2 := time.Now()
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, nil, tm, fmt.Errorf("TLS handshake with %s: %w", r.Addr, err)
	}
	tm.handshake = MS(time.Since(t2))
	cs := tc.ConnectionState()
	return &cs, tc, tm, nil
}

// Verify checks the chain against base.RootCAs (system roots when nil) and,
// when name is set, the leaf against name.
func Verify(chain []*x509.Certificate, base *tls.Config, name string, now time.Time) Verification {
	v := Verification{RootSource: "system"}
	if len(chain) == 0 {
		v.ChainError = "server presented no certificates"
		return v
	}
	opts := x509.VerifyOptions{CurrentTime: now, Intermediates: x509.NewCertPool()}
	if base != nil && base.RootCAs != nil {
		opts.Roots = base.RootCAs
		v.RootSource = "system + ca_cert"
	}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	leaf := chain[0]
	chains, err := leaf.Verify(opts)
	if err != nil {
		v.ChainError = err.Error()
	} else {
		v.ChainValid = true
		for _, ch := range chains {
			var names []string
			for _, c := range ch {
				names = append(names, c.Subject.String())
			}
			v.VerifiedChains = append(v.VerifiedChains, names)
		}
	}
	v.Trusted = v.ChainValid
	if name != "" {
		v.VerifiedName = name
		ok := true
		if err := leaf.VerifyHostname(name); err != nil {
			ok = false
			v.HostnameError = err.Error()
			v.Trusted = false
		}
		v.HostnameValid = &ok
	}
	return v
}

// DescribeCert summarises a certificate.
func DescribeCert(c *x509.Certificate, now time.Time, includePEM bool) CertInfo {
	sum := sha256.Sum256(c.Raw)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		parts = append(parts, fp[i:i+2])
	}
	info := CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		CommonName:         c.Subject.CommonName,
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		SerialNumber:       formatSerial(c),
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry:    int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		Expired:            now.After(c.NotAfter),
		NotYetValid:        now.Before(c.NotBefore),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		PublicKeySize:      keyBits(c.PublicKey),
		SHA256Fingerprint:  strings.Join(parts, ":"),
		IsCA:               c.IsCA,
		OCSPServers:        c.OCSPServer,
		IssuingCertURL:     c.IssuingCertificateURL,
	}
	for _, ip := range c.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	if c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil {
		info.SelfSigned = true
	}
	info.KeyUsage = keyUsages(c.KeyUsage)
	for _, u := range c.ExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, extKeyUsageName(u))
	}
	if includePEM {
		info.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return info
}

func formatSerial(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	h := strings.ToUpper(c.SerialNumber.Text(16))
	if len(h)%2 == 1 {
		h = "0" + h
	}
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyBits(k any) int {
	switch v := k.(type) {
	case *rsa.PublicKey:
		return v.N.BitLen()
	case *ecdsa.PublicKey:
		return v.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

func keyUsages(ku x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	var out []string
	for _, n := range names {
		if ku&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "server_auth"
	case x509.ExtKeyUsageClientAuth:
		return "client_auth"
	case x509.ExtKeyUsageCodeSigning:
		return "code_signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email_protection"
	case x509.ExtKeyUsageTimeStamping:
		return "time_stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocsp_signing"
	}
	return fmt.Sprintf("ext_key_usage_%d", u)
}
