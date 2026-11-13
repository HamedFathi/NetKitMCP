// Package tlsx builds tls.Config values from the shared TLS options.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// LoadPEM returns inline PEM as-is, or reads it from an allowed file.
func LoadPEM(files *fileio.Policy, v string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	return files.ReadSmall(v, 1<<20)
}

// Config builds a client tls.Config. serverName is used when opts.ServerName
// is empty (may be ""). alpn may be nil.
func Config(files *fileio.Policy, opts types.TLSOptions, serverName string, alpn []string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // explicit, flagged in results
		ServerName:         serverName,
		NextProtos:         alpn,
	}
	if opts.ServerName != "" {
		cfg.ServerName = opts.ServerName
	}
	if opts.CACert != "" {
		pem, err := LoadPEM(files, opts.CACert)
		if err != nil {
			return nil, fmt.Errorf("ca_cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert: no certificates found in PEM")
		}
		cfg.RootCAs = pool
	}
	if opts.ClientCert != "" || opts.ClientKey != "" {
		if opts.ClientCert == "" || opts.ClientKey == "" {
			return nil, fmt.Errorf("client_cert and client_key must both be set")
		}
		certPEM, err := LoadPEM(files, opts.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("client_cert: %w", err)
		}
		keyPEM, err := LoadPEM(files, opts.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("client_key: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Info summarises a connection state.
func Info(cs *tls.ConnectionState, insecure bool) *types.TLSInfo {
	if cs == nil {
		return nil
	}
	info := &types.TLSInfo{
		Version:            tls.VersionName(cs.Version),
		Cipher:             tls.CipherSuiteName(cs.CipherSuite),
		ALPN:               cs.NegotiatedProtocol,
		InsecureSkipVerify: insecure,
	}
	if len(cs.PeerCertificates) > 0 {
		info.PeerCN = cs.PeerCertificates[0].Subject.CommonName
	}
	return info
}
