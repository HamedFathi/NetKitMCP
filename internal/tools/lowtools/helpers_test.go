package lowtools_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// testCA is a throwaway certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  string
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netkit test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// leaf issues a server certificate for localhost/127.0.0.1 valid in [nb, na].
func (ca *testCA) leaf(t *testing.T, nb, na time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    nb,
		NotAfter:     na,
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

func (ca *testCA) validLeaf(t *testing.T) tls.Certificate {
	return ca.leaf(t, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour+time.Hour))
}

// listen starts a TCP listener on loopback and serves each connection with fn.
func listen(t *testing.T, fn func(net.Conn)) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				fn(c)
			}()
		}
	}()
	return splitAddr(t, ln.Addr().String())
}

// listenTLS is listen with a TLS wrapper.
func listenTLS(t *testing.T, cfg *tls.Config, fn func(net.Conn)) (string, int) {
	t.Helper()
	return listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		fn(tc)
	})
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func withAllowPorts(ports ...int) tooltest.Option {
	return func(c *config.Config) { c.AllowPorts = ports }
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}
