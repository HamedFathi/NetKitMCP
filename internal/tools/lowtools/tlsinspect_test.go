package lowtools_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func tlsServer(t *testing.T, cfg *tls.Config) (string, int) {
	return listenTLS(t, cfg, func(c net.Conn) {})
}

func verification(r *tooltest.Result) map[string]any { return r.Data["verification"].(map[string]any) }

func TestTLSInspectTrustedWithCACert(t *testing.T) {
	ca := newCA(t)
	host, port := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}, NextProtos: []string{"h2", "http/1.1"}})
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tls_inspect", map[string]any{"host": host, "port": port, "server_name": "localhost", "ca_cert": ca.PEM,
		"alpn": []string{"h2"}, "include_pem": true})
	v := verification(r)
	if v["trusted"] != true || v["chain_valid"] != true || v["hostname_valid"] != true {
		t.Fatalf("verification: %v", v)
	}
	if r.Data["version"] != "TLS 1.3" || r.Data["alpn"] != "h2" || r.Data["ocsp_stapled"] != false {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	chain := r.Data["chain"].([]any)
	if len(chain) != 2 {
		t.Fatalf("chain length %d", len(chain))
	}
	leaf := chain[0].(map[string]any)
	if leaf["common_name"] != "localhost" || leaf["is_ca"] != false || num(leaf["days_until_expiry"]) != 30 ||
		!strings.Contains(fmt.Sprint(leaf["dns_names"]), "localhost") || !strings.Contains(fmt.Sprint(leaf["ip_addresses"]), "127.0.0.1") ||
		len(leaf["sha256_fingerprint"].(string)) != 95 || !strings.HasPrefix(leaf["pem"].(string), "-----BEGIN CERTIFICATE") {
		t.Fatalf("leaf: %v", leaf)
	}
	if root := chain[1].(map[string]any); root["is_ca"] != true || root["self_signed"] != true {
		t.Fatalf("root: %v", root)
	}
	// Verifying the IP address (no server_name) also works via the IP SAN.
	r = h.MustOK("tls_inspect", map[string]any{"host": fmt.Sprintf("%s:%d", host, port), "ca_cert": ca.PEM})
	if verification(r)["trusted"] != true {
		t.Fatalf("ip verification: %s", r.Raw)
	}
}

func TestTLSInspectFailuresAreReported(t *testing.T) {
	ca := newCA(t)
	host, port := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}})
	h := tooltest.New(t, "lowlevel")

	// Untrusted: no ca_cert, so the private CA is unknown.
	r := h.MustOK("tls_inspect", map[string]any{"host": host, "port": port, "server_name": "localhost"})
	v := verification(r)
	if v["trusted"] != false || v["chain_valid"] != false || v["chain_error"] == "" || v["hostname_valid"] != true {
		t.Fatalf("untrusted: %v", v)
	}

	// Hostname mismatch: chain is fine, the name is not.
	r = h.MustOK("tls_inspect", map[string]any{"host": host, "port": port, "server_name": "wrong.example", "ca_cert": ca.PEM})
	v = verification(r)
	if v["trusted"] != false || v["chain_valid"] != true || v["hostname_valid"] != false || !strings.Contains(v["hostname_error"].(string), "wrong.example") {
		t.Fatalf("mismatch: %v", v)
	}

	// Expired leaf.
	expired := ca.leaf(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	eh, ep := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{expired}})
	r = h.MustOK("tls_inspect", map[string]any{"host": eh, "port": ep, "server_name": "localhost", "ca_cert": ca.PEM})
	v = verification(r)
	leaf := r.Data["chain"].([]any)[0].(map[string]any)
	if v["trusted"] != false || v["chain_valid"] != false || !strings.Contains(v["chain_error"].(string), "expired") ||
		leaf["expired"] != true || num(leaf["days_until_expiry"]) >= 0 {
		t.Fatalf("expired: %v / %v", v, leaf)
	}
	if !strings.Contains(fmt.Sprint(r.Data["warnings"]), "expired") {
		t.Fatalf("missing expiry warning: %s", r.Raw)
	}
}

func TestTLSInspectHTTPTestAndProbe(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tls_inspect", map[string]any{"host": ts.URL, "probe_versions": true, "max_version": "1.2"})
	if r.Data["version"] != "TLS 1.2" {
		t.Fatalf("version: %s", r.Raw)
	}
	got := map[string]bool{}
	for _, p := range r.Data["supported_versions"].([]any) {
		pm := p.(map[string]any)
		got[pm["version"].(string)] = pm["supported"].(bool)
	}
	if got["TLS 1.0"] || got["TLS 1.1"] || !got["TLS 1.2"] || !got["TLS 1.3"] {
		t.Fatalf("probe: %v", got)
	}
	h.MustFail("tls_inspect", map[string]any{"host": ts.URL, "min_version": "1.3", "max_version": "1.2"}, "min_version")
	h.MustFail("tls_inspect", map[string]any{"host": ts.URL, "min_version": "2.0"}, "unknown TLS version")
}

func TestTLSInspectSTARTTLS(t *testing.T) {
	ca := newCA(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}}
	host, port := listen(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		fmt.Fprint(c, "220 mail.test ESMTP\r\n")
		if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "EHLO") {
			return
		}
		fmt.Fprint(c, "250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
		if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "STARTTLS") {
			return
		}
		fmt.Fprint(c, "220 go ahead\r\n")
		tls.Server(c, cfg).Handshake()
	})
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tls_inspect", map[string]any{"host": host, "port": port, "starttls": "smtp", "server_name": "localhost", "ca_cert": ca.PEM})
	if r.Data["starttls"] != "smtp" || verification(r)["trusted"] != true {
		t.Fatalf("starttls: %s", r.Raw)
	}
	h.MustFail("tls_inspect", map[string]any{"host": host, "port": port, "starttls": "xmpp"}, "unsupported starttls")
}

func TestTLSInspectGuard(t *testing.T) {
	ca := newCA(t)
	host, port := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}})
	h := tooltest.New(t, "lowlevel", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("tls_inspect", map[string]any{"host": host, "port": port}, "allow_private")
	h.MustOK("tls_inspect", map[string]any{"host": host, "port": port, "allow_private": true})
}
