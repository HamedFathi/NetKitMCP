package soap

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// WS-Security namespaces and URIs (OASIS WSS 1.0 UsernameToken Profile).
const (
	NSWSSE          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NSWSU           = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	PasswordTextURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
	PasswordDigURI  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	Base64BinaryURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	wsuTimeFormat   = "2006-01-02T15:04:05.000Z"
)

// WSSecurity describes a wsse:Security header with a UsernameToken and an
// optional Timestamp. Signing and encryption are not supported.
type WSSecurity struct {
	Username       string
	Password       string
	Digest         bool          // PasswordDigest instead of PasswordText
	Timestamp      bool          // add wsu:Timestamp
	TTL            time.Duration // timestamp lifetime (default 5 minutes)
	MustUnderstand bool
	Now            time.Time // zero = time.Now()
	Nonce          []byte    // nil = 16 random bytes
}

// PasswordDigest computes Base64(SHA-1(nonce + created + password)), where
// nonce is the raw (decoded) nonce bytes.
func PasswordDigest(nonce []byte, created, password string) string {
	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(created))
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ParsePasswordType maps text/digest (and the full URIs) to Digest.
func ParsePasswordType(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "text", "passwordtext", strings.ToLower(PasswordTextURI):
		return false, nil
	case "digest", "passworddigest", strings.ToLower(PasswordDigURI):
		return true, nil
	}
	return false, fmt.Errorf("ws_security password_type must be text or digest, got %q", v)
}

// Header renders the wsse:Security header block for the SOAP version.
func (w WSSecurity) Header(version string) (string, error) {
	if w.Username == "" {
		return "", errors.New("auth ws_security: username is required")
	}
	now := w.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	nonce := w.Nonce
	if nonce == nil {
		nonce = make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	created := now.Format(wsuTimeFormat)
	var b strings.Builder
	b.WriteString(`<wsse:Security xmlns:wsse="` + NSWSSE + `" xmlns:wsu="` + NSWSU + `"`)
	if w.MustUnderstand {
		mu := "1"
		if version == "1.2" {
			mu = "true"
		}
		fmt.Fprintf(&b, ` xmlns:soapenv="%s" soapenv:mustUnderstand="%s"`, EnvNS(version), mu)
	}
	b.WriteString(">")
	if w.Timestamp {
		ttl := w.TTL
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		fmt.Fprintf(&b, `<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>%s</wsu:Created><wsu:Expires>%s</wsu:Expires></wsu:Timestamp>`,
			created, now.Add(ttl).Format(wsuTimeFormat))
	}
	pwType, pw := PasswordTextURI, w.Password
	if w.Digest {
		pwType, pw = PasswordDigURI, PasswordDigest(nonce, created, w.Password)
	}
	fmt.Fprintf(&b, `<wsse:UsernameToken wsu:Id="UsernameToken-1"><wsse:Username>%s</wsse:Username>`, escAttr(w.Username))
	fmt.Fprintf(&b, `<wsse:Password Type="%s">%s</wsse:Password>`, pwType, escAttr(pw))
	fmt.Fprintf(&b, `<wsse:Nonce EncodingType="%s">%s</wsse:Nonce>`, Base64BinaryURI, base64.StdEncoding.EncodeToString(nonce))
	fmt.Fprintf(&b, `<wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security>`, created)
	return b.String(), nil
}
