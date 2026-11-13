package soaptools_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// A server that echoes the request envelope back must not leak the
// WS-Security password through raw_xml.
func TestRawXMLEchoRedactsPassword(t *testing.T) {
	const password = "Echo-Secret-77"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Write(b)
	}))
	defer srv.Close()
	h := tooltest.New(t, "soap")
	r := h.MustOK("soap_request", map[string]any{
		"endpoint": srv.URL, "raw_body": `<p:Ping xmlns:p="urn:p"/>`,
		"auth": map[string]any{"type": "ws_security", "username": "alice", "password": password},
	})
	if strings.Contains(string(r.Raw), password) || strings.Contains(r.Text, password) {
		t.Fatalf("password leaked in result:\n%s", r.Raw)
	}
	if !strings.Contains(string(r.Raw), "Ping") {
		t.Fatalf("raw_xml missing echoed body:\n%s", r.Raw)
	}
}
