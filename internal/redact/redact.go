// Package redact masks secrets in echoed request details and logs.
package redact

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const mask = "***"

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-amz-security-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "private-token": true, "x-access-token": true,
}

var sensitiveWords = []string{"token", "secret", "password", "passwd", "apikey", "api_key", "api-key",
	"signature", "credential", "session", "auth", "private_key", "privatekey", "client_secret"}

// IsSensitiveName reports whether a header/param/field name looks secret.
func IsSensitiveName(name string) bool {
	n := strings.ToLower(name)
	if sensitiveHeaders[n] {
		return true
	}
	for _, w := range sensitiveWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// Value masks a secret, keeping a short prefix for recognisability.
func Value(v string) string {
	if v == "" {
		return ""
	}
	if fields := strings.Fields(v); len(fields) == 2 && len(fields[0]) < 16 {
		// "Bearer xxx" -> "Bearer ***"
		return fields[0] + " " + mask
	}
	return mask
}

// Headers returns a flattened, redacted copy of h.
func Headers(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		if IsSensitiveName(k) {
			v = Value(v)
		}
		out[k] = v
	}
	return out
}

// Map returns a redacted copy of a string map.
func Map(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if IsSensitiveName(k) {
			v = Value(v)
		}
		out[k] = v
	}
	return out
}

// URL masks userinfo passwords and sensitive query parameters.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), mask)
		}
	}
	q := u.Query()
	changed := false
	for k := range q {
		if IsSensitiveName(k) || strings.HasPrefix(strings.ToLower(k), "x-amz-") && strings.Contains(strings.ToLower(k), "sig") {
			q.Set(k, mask)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

var (
	// A Password element with any XML NCName prefix (letters, digits, '-',
	// '.', '_'), exactly named Password (not PasswordHint), with optional
	// attributes. RE2 has no backreferences, so the closing tag is matched
	// by name with any prefix.
	wsPassword = regexp.MustCompile(`(?s)(<(?:[\pL_][\pL\pN._\-]*:)?Password(?:\s[^>]*)?>).*?(</(?:[\pL_][\pL\pN._\-]*:)?Password\s*>)`)
	pemBlock   = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
)

// Text masks WS-Security passwords and PEM private keys inside free text.
func Text(s string) string {
	s = wsPassword.ReplaceAllString(s, "${1}"+mask+"${2}")
	s = pemBlock.ReplaceAllString(s, "-----PRIVATE KEY REDACTED-----")
	return s
}
