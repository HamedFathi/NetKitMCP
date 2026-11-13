package httptools_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/HamedFathi/NetKitMCP/internal/tools/httptools" // registers the tools
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// response mirrors the http_* tool result.
type response struct {
	types.HTTPResponse
	UploadedFiles []types.FileInfo `json:"uploaded_files"`
	Request       *struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    *struct {
			Kind      string           `json:"kind"`
			SizeBytes int64            `json:"size_bytes"`
			SHA256    string           `json:"sha256"`
			Files     []types.FileInfo `json:"files"`
		} `json:"body"`
	} `json:"request"`
}

func call(t *testing.T, h *tooltest.Harness, tool string, args map[string]any) response {
	t.Helper()
	r := h.MustOK(tool, args)
	var out response
	r.Decode(t, &out)
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// pattern returns n deterministic pseudo-random bytes.
func pattern(n int) []byte {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

// writeBig writes n pattern bytes to the readable dir and returns path and hash.
func writeBig(t *testing.T, h *tooltest.Harness, name string, n int) (string, string) {
	t.Helper()
	data := pattern(n)
	p := filepath.Join(h.ReadDir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p, sha(data)
}

// selfSigned returns a certificate for 127.0.0.1/localhost and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netkit-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, string(certPEM)
}
