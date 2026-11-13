package httptools_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/quic-go/http3"

	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// protoHandler answers with the protocol the server saw.
var protoHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, r.Proto)
})

func TestHTTPVersions(t *testing.T) {
	cert, caPEM := selfSigned(t)
	srv := httptest.NewUnstartedServer(protoHandler)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	h := tooltest.New(t, "http")
	for _, tc := range []struct{ version, want string }{
		{"", "HTTP/2.0"}, // negotiated via ALPN
		{"1.1", "HTTP/1.1"},
		{"2", "HTTP/2.0"},
	} {
		out := call(t, h, "http_request", map[string]any{"url": srv.URL, "ca_cert": caPEM, "http_version": tc.version})
		if out.Status != 200 || out.Body != tc.want || out.Protocol != tc.want {
			t.Fatalf("http_version %q: status %d body %q protocol %q, want %s", tc.version, out.Status, out.Body, out.Protocol, tc.want)
		}
	}
	h.MustFail("http_request", map[string]any{"url": srv.URL, "ca_cert": caPEM, "http_version": "4"}, "unsupported http_version")
}

func TestHTTP3(t *testing.T) {
	cert, caPEM := selfSigned(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: protoHandler, TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})}
	go srv.Serve(pc)
	defer srv.Close()
	url := "https://" + pc.LocalAddr().String() + "/"

	h := tooltest.New(t, "http")
	out := call(t, h, "http_request", map[string]any{"url": url, "ca_cert": caPEM, "http_version": "3", "timeout_seconds": 10})
	if out.Status != 200 || out.Body != "HTTP/3.0" {
		t.Fatalf("status %d body %q protocol %q", out.Status, out.Body, out.Protocol)
	}
	if out.TLS == nil || out.TLS.Version != "TLS 1.3" {
		t.Fatalf("tls info: %+v", out.TLS)
	}
	// An untrusted certificate fails over QUIC too.
	h.MustFail("http_request", map[string]any{"url": url, "http_version": "3", "timeout_seconds": 5}, "")
	// HTTP/3 cannot be tunnelled through an HTTP proxy.
	h.MustFail("http_request", map[string]any{"url": url, "http_version": "3", "proxy": "http://127.0.0.1:1"}, "proxy")
}
