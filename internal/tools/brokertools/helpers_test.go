package brokertools_test

import (
	"crypto/tls"
	"encoding/pem"
	"net/http/httptest"
	"testing"

	_ "github.com/HamedFathi/NetKitMCP/internal/tools/brokertools"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// testTLS returns a server TLS config with a certificate for 127.0.0.1 and
// the PEM of the certificate to trust (borrowed from httptest).
func testTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	s := httptest.NewUnstartedServer(nil)
	s.StartTLS()
	cert := s.Certificate()
	cfg := &tls.Config{Certificates: s.TLS.Certificates, MinVersion: tls.VersionTLS12}
	s.Close()
	return cfg, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func stream(t *testing.T, r *tooltest.Result) types.StreamResult {
	t.Helper()
	var s types.StreamResult
	r.Decode(t, &s)
	return s
}
