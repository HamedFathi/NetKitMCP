package sftpx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestWildcardMatch(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"[127.0.0.1]:2222", "[127.0.0.1]:2222", true},
		{"[127.0.0.1]:2222", "[127.0.0.1]:2223", false},
		{"[127.0.0.1]:2222", "1:2222", false}, // not a character class
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"host?", "host1", true},
		{"host?", "host12", false},
		{"*", "", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"[*]:22*", "[10.0.0.1]:2222", true},
	} {
		if got := wildcardMatch(c.pat, c.s); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestMatchHost(t *testing.T) {
	if !matchHost([]string{"*.corp", "!bad.corp"}, []string{"good.corp"}) {
		t.Error("good.corp should match")
	}
	if matchHost([]string{"*.corp", "!bad.corp"}, []string{"bad.corp"}) {
		t.Error("negated pattern must win")
	}
	hashed := knownhosts.HashHostname("[10.1.2.3]:2022")
	if !matchHost([]string{hashed}, []string{"[10.1.2.3]:2022"}) || matchHost([]string{hashed}, []string{"10.1.2.3"}) {
		t.Error("hashed host matching")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	k := newPub(t)
	sha := ssh.FingerprintSHA256(k)
	md5 := ssh.FingerprintLegacyMD5(k)
	for _, fp := range []string{sha, strings.ToLower(sha[:7]) + sha[7:], sha + "=", "MD5:" + md5, md5, strings.ReplaceAll(md5, ":", "")} {
		if !fingerprintMatches(fp, k) {
			t.Errorf("fingerprint %q should match", fp)
		}
	}
	if fingerprintMatches(ssh.FingerprintSHA256(newPub(t)), k) {
		t.Error("another key's fingerprint matched")
	}
	for _, bad := range []string{"SHA256:!!", "abc", "MD5:zz"} {
		if _, _, err := normalizeFingerprint(bad); err == nil {
			t.Errorf("normalizeFingerprint(%q) should fail", bad)
		}
	}
}

func TestVerifierKnownHosts(t *testing.T) {
	k, other := newPub(t), newPub(t)
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	host := "127.0.0.1:2222"
	check := func(kh string, key ssh.PublicKey) (*Verifier, error) {
		v, err := NewVerifier(HostKeyPolicy{KnownHosts: []byte(kh)})
		if err != nil {
			t.Fatal(err)
		}
		return v, v.Callback()(host, addr, key)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(host)}, k)
	v, err := check(line+"\n", k)
	if err != nil || !v.Observed.Verified || v.Observed.VerifiedBy != "known_hosts" {
		t.Fatalf("known host: %v %+v", err, v.Observed)
	}
	// Hashed entry.
	if _, err := check("|1|"+strings.TrimPrefix(knownhosts.HashHostname(knownhosts.Normalize(host)), "|1|")+" "+strings.SplitN(line, " ", 2)[1], k); err != nil {
		t.Fatalf("hashed entry: %v", err)
	}
	// Mismatch, unknown host, revoked.
	if _, err := check(line, other); err == nil || !strings.Contains(err.Error(), "MISMATCH") || !errors.Is(err, ErrHostKey) {
		t.Fatalf("mismatch: %v", err)
	}
	if _, err := check(knownhosts.Line([]string{"[127.0.0.1]:22"}, k), k); err == nil || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Fatalf("other port: %v", err)
	}
	if _, err := check(line+"\n@revoked * "+strings.SplitN(line, " ", 2)[1], k); err == nil || !strings.Contains(err.Error(), "@revoked") {
		t.Fatalf("revoked: %v", err)
	}
	// The algorithm preference follows the known key type for the port.
	if algos := HostKeyAlgorithms([]byte(line), host); len(algos) != 1 || algos[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("HostKeyAlgorithms: %v", algos)
	}
}

func TestVerifierPolicy(t *testing.T) {
	k := newPub(t)
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	v, _ := NewVerifier(HostKeyPolicy{})
	if err := v.Callback()("127.0.0.1:22", addr, k); err == nil || !strings.Contains(err.Error(), "verification is required") {
		t.Fatalf("no policy: %v", err)
	}
	v, _ = NewVerifier(HostKeyPolicy{Insecure: true})
	if err := v.Callback()("127.0.0.1:22", addr, k); err != nil || v.Observed.Verified || v.Observed.VerifiedBy != "insecure_ignore_host_key" {
		t.Fatalf("insecure: %v %+v", err, v.Observed)
	}
	v, _ = NewVerifier(HostKeyPolicy{Insecure: true, Fingerprint: ssh.FingerprintSHA256(newPub(t))})
	if err := v.Callback()("127.0.0.1:22", addr, k); err == nil {
		t.Fatal("a pinned fingerprint must be checked even with insecure set")
	}
	if _, err := NewVerifier(HostKeyPolicy{KnownHosts: []byte("# only a comment\n")}); err == nil {
		t.Fatal("empty known_hosts should be rejected")
	}
}

func TestLooksLikeKnownHosts(t *testing.T) {
	k := newPub(t)
	if !LooksLikeKnownHosts(knownhosts.Line([]string{"h"}, k)) || !LooksLikeKnownHosts("a\nb") {
		t.Error("inline content not detected")
	}
	if LooksLikeKnownHosts(`C:\Users\me\.ssh\known_hosts`) || LooksLikeKnownHosts("/home/me/.ssh/known_hosts") || LooksLikeKnownHosts(`C:\Users\x y\My ssh-files\known_hosts`) {
		t.Error("path detected as content")
	}
}
