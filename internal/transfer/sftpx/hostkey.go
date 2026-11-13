package sftpx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKey is wrapped by every host-key verification failure.
var ErrHostKey = errors.New("SSH host key verification failed")

// HostKeyPolicy says how the server's host key is verified. At least one of
// KnownHosts, Fingerprint or Insecure must be set.
type HostKeyPolicy struct {
	// KnownHosts is the contents of a known_hosts file.
	KnownHosts []byte
	// Fingerprint is a pinned key fingerprint: "SHA256:<base64>" or a legacy
	// MD5 fingerprint ("MD5:aa:bb:..", "aa:bb:..." or 32 hex digits).
	Fingerprint string
	// Insecure skips verification (the observed key is still reported).
	Insecure bool
}

// HostKeyInfo describes the key the server presented.
type HostKeyInfo struct {
	Type              string `json:"type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	FingerprintMD5    string `json:"fingerprint_md5"`
	VerifiedBy        string `json:"verified_by"`
	Verified          bool   `json:"verified"`
}

type knownEntry struct {
	marker   string // "", "@cert-authority", "@revoked"
	patterns []string
	key      ssh.PublicKey
}

func parseKnownHosts(data []byte) ([]knownEntry, error) {
	var out []knownEntry
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		marker, hosts, key, _, r, err := ssh.ParseKnownHosts(rest)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("known_hosts: %w", err)
		}
		rest = r
		e := knownEntry{key: key, patterns: hosts}
		switch marker {
		case "cert-authority":
			e.marker = "@cert-authority"
		case "revoked":
			e.marker = "@revoked"
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, errors.New("known_hosts: no host keys found")
	}
	return out, nil
}

// LooksLikeKnownHosts reports whether s is inline known_hosts content
// rather than a file path.
func LooksLikeKnownHosts(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "\n") {
		return true
	}
	f := strings.Fields(s)
	if len(f) >= 3 && (strings.HasPrefix(f[0], "@") || strings.Contains(f[1], "ssh-") || strings.HasPrefix(f[1], "ecdsa-") || strings.HasPrefix(f[1], "sk-")) {
		return true
	}
	return false
}

func matchPattern(pattern, host string) bool {
	if strings.HasPrefix(pattern, "|1|") {
		parts := strings.Split(pattern[3:], "|")
		if len(parts) != 2 {
			return false
		}
		salt, err1 := base64.StdEncoding.DecodeString(parts[0])
		want, err2 := base64.StdEncoding.DecodeString(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		m := hmac.New(sha1.New, salt)
		m.Write([]byte(host))
		return hmac.Equal(m.Sum(nil), want)
	}
	return wildcardMatch(strings.ToLower(pattern), strings.ToLower(host))
}

// wildcardMatch implements OpenSSH host pattern matching: "*" matches any
// run of characters and "?" exactly one; everything else (including the
// "[" and "]" of "[host]:port" entries) is literal.
func wildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matchHost reports whether any of the patterns matches one of the
// candidate names, honouring negated patterns.
func matchHost(patterns []string, candidates []string) bool {
	matched := false
	for _, c := range candidates {
		for _, p := range patterns {
			neg := strings.HasPrefix(p, "!")
			if neg {
				p = p[1:]
			}
			if matchPattern(p, c) {
				if neg {
					return false
				}
				matched = true
			}
		}
	}
	return matched
}

func keyEqual(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// candidates returns the normalised names to look up: the host as dialled
// and the remote IP, each in known_hosts form ("host" or "[host]:port").
func candidates(hostport string, remote net.Addr) []string {
	out := []string{knownhosts.Normalize(hostport)}
	if remote != nil {
		if n := knownhosts.Normalize(remote.String()); n != out[0] {
			out = append(out, n)
		}
	}
	return out
}

// HostKeyAlgorithms returns the algorithms to offer so the server presents
// a key type known for this host (nil when no preference applies).
func HostKeyAlgorithms(knownHosts []byte, hostport string) []string {
	entries, err := parseKnownHosts(knownHosts)
	if err != nil {
		return nil
	}
	cands := candidates(hostport, nil)
	seen := map[string]bool{}
	var algos []string
	add := func(a ...string) {
		for _, x := range a {
			if !seen[x] {
				seen[x] = true
				algos = append(algos, x)
			}
		}
	}
	hasCA := false
	for _, e := range entries {
		if e.marker == "@revoked" || !matchHost(e.patterns, cands) {
			continue
		}
		if e.marker == "@cert-authority" {
			hasCA = true
			continue
		}
		switch t := e.key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			add(t)
		}
	}
	if len(algos) == 0 || hasCA {
		return nil
	}
	return algos
}

// Verifier builds the host key callback and records what was observed.
type Verifier struct {
	policy   HostKeyPolicy
	entries  []knownEntry
	Observed *HostKeyInfo
}

// NewVerifier validates the policy.
func NewVerifier(p HostKeyPolicy) (*Verifier, error) {
	v := &Verifier{policy: p}
	if len(p.KnownHosts) > 0 {
		e, err := parseKnownHosts(p.KnownHosts)
		if err != nil {
			return nil, err
		}
		v.entries = e
	}
	if p.Fingerprint != "" {
		if _, _, err := normalizeFingerprint(p.Fingerprint); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func normalizeFingerprint(fp string) (kind, value string, err error) {
	fp = strings.TrimSpace(fp)
	switch {
	case strings.HasPrefix(strings.ToUpper(fp), "SHA256:"):
		v := strings.TrimRight(fp[7:], "=")
		if _, err := base64.RawStdEncoding.DecodeString(v); err != nil {
			return "", "", fmt.Errorf("host_key_fingerprint %q: invalid base64", fp)
		}
		return "sha256", v, nil
	case strings.HasPrefix(strings.ToUpper(fp), "MD5:"):
		fp = fp[4:]
	}
	h := strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	if len(h) != 32 {
		return "", "", fmt.Errorf("host_key_fingerprint %q: want SHA256:<base64> or an MD5 hex fingerprint", fp)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", "", fmt.Errorf("host_key_fingerprint %q: invalid hex", fp)
	}
	return "md5", h, nil
}

func fingerprintMatches(pinned string, key ssh.PublicKey) bool {
	kind, val, err := normalizeFingerprint(pinned)
	if err != nil {
		return false
	}
	if kind == "sha256" {
		got := strings.TrimPrefix(ssh.FingerprintSHA256(key), "SHA256:")
		return strings.TrimRight(got, "=") == val
	}
	return strings.ReplaceAll(ssh.FingerprintLegacyMD5(key), ":", "") == val
}

// Callback returns the ssh.HostKeyCallback implementing the policy.
func (v *Verifier) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		plain := key
		if cert, ok := key.(*ssh.Certificate); ok {
			plain = cert.Key
		}
		info := &HostKeyInfo{
			Type:              key.Type(),
			FingerprintSHA256: ssh.FingerprintSHA256(plain),
			FingerprintMD5:    ssh.FingerprintLegacyMD5(plain),
		}
		v.Observed = info
		p := v.policy
		var by []string
		if len(v.entries) > 0 {
			if err := v.checkKnownHosts(hostname, remote, key); err != nil {
				return err
			}
			by = append(by, "known_hosts")
		}
		if p.Fingerprint != "" {
			if !fingerprintMatches(p.Fingerprint, plain) {
				return fmt.Errorf("%w: the server's %s key %s does not match the pinned fingerprint %s (possible man-in-the-middle, or the key changed)",
					ErrHostKey, key.Type(), info.FingerprintSHA256, p.Fingerprint)
			}
			by = append(by, "fingerprint")
		}
		if len(by) == 0 {
			if p.Insecure {
				info.VerifiedBy = "insecure_ignore_host_key"
				return nil
			}
			return fmt.Errorf("%w: host key verification is required. Set auth.ssh.known_hosts or auth.ssh.host_key_fingerprint (the server presented %s %s), or set auth.ssh.insecure_ignore_host_key=true to skip verification",
				ErrHostKey, key.Type(), info.FingerprintSHA256)
		}
		info.Verified = true
		info.VerifiedBy = strings.Join(by, "+")
		return nil
	}
}

func (v *Verifier) checkKnownHosts(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cands := candidates(hostname, remote)
	var known []ssh.PublicKey
	var cas []ssh.PublicKey
	for _, e := range v.entries {
		if !matchHost(e.patterns, cands) && !(e.marker == "@revoked") {
			continue
		}
		switch e.marker {
		case "@revoked":
			k := key
			if c, ok := key.(*ssh.Certificate); ok {
				if keyEqual(c.SignatureKey, e.key) {
					return fmt.Errorf("%w: the host certificate's CA key is marked @revoked in known_hosts", ErrHostKey)
				}
				k = c.Key
			}
			if keyEqual(k, e.key) {
				return fmt.Errorf("%w: the server's %s key is marked @revoked in known_hosts", ErrHostKey, key.Type())
			}
		case "@cert-authority":
			cas = append(cas, e.key)
		default:
			known = append(known, e.key)
		}
	}
	if cert, ok := key.(*ssh.Certificate); ok && len(cas) > 0 {
		checker := &ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
				for _, ca := range cas {
					if keyEqual(ca, auth) {
						return true
					}
				}
				return false
			},
		}
		if err := checker.CheckHostKey(hostname, remote, cert); err != nil {
			return fmt.Errorf("%w: host certificate: %v", ErrHostKey, err)
		}
		return nil
	}
	plain := key
	if cert, ok := key.(*ssh.Certificate); ok {
		plain = cert.Key
	}
	for _, k := range known {
		if keyEqual(k, plain) {
			return nil
		}
	}
	if len(known) > 0 {
		types := map[string]bool{}
		for _, k := range known {
			types[k.Type()] = true
		}
		sameType := types[plain.Type()]
		if sameType {
			return fmt.Errorf("%w: REMOTE HOST KEY MISMATCH for %s: the server presented %s %s, which differs from known_hosts (possible man-in-the-middle, or the host key changed)",
				ErrHostKey, cands[0], plain.Type(), ssh.FingerprintSHA256(plain))
		}
		return fmt.Errorf("%w: known_hosts has no %s key for %s (the server presented %s); add it or pin host_key_fingerprint",
			ErrHostKey, plain.Type(), cands[0], ssh.FingerprintSHA256(plain))
	}
	return fmt.Errorf("%w: %s is not in known_hosts (the server presented %s %s); add it or pin host_key_fingerprint",
		ErrHostKey, cands[0], plain.Type(), ssh.FingerprintSHA256(plain))
}
