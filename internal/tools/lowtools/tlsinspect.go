package lowtools

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type tlsInspectIn struct {
	Host          string   `json:"host" jsonschema:"server hostname or IP (may include :port); a https:// URL is also accepted"`
	Port          int      `json:"port,omitempty" jsonschema:"TCP port (default 443, or the STARTTLS protocol's port)"`
	ALPN          []string `json:"alpn,omitempty" jsonschema:"ALPN protocols to offer, e.g. [\"h2\",\"http/1.1\"]"`
	MinVersion    string   `json:"min_version,omitempty" jsonschema:"minimum TLS version to offer: 1.0, 1.1, 1.2 or 1.3 (default 1.0)"`
	MaxVersion    string   `json:"max_version,omitempty" jsonschema:"maximum TLS version to offer (default 1.3)"`
	ProbeVersions bool     `json:"probe_versions,omitempty" jsonschema:"also probe which of TLS 1.0, 1.1, 1.2 and 1.3 the server accepts"`
	StartTLS      string   `json:"starttls,omitempty" jsonschema:"upgrade a plaintext protocol first: smtp, imap, pop3 or ftp"`
	IncludePEM    bool     `json:"include_pem,omitempty" jsonschema:"include each certificate as PEM"`
	types.NetOptions
}

var starttlsPorts = map[string]int{"smtp": 25, "imap": 143, "pop3": 110, "ftp": 21}

func registerTLSInspect(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "tls_inspect", "Inspect TLS",
		"Connect to a TLS server and report the negotiated version, cipher, ALPN, OCSP stapling and the full certificate chain "+
			"(subject, issuer, SANs, validity, days_until_expiry, algorithms, SHA-256 fingerprint). Verification against system roots "+
			"(plus ca_cert) and the hostname is reported separately (verification.trusted, chain_error, hostname_error), so expired, "+
			"self-signed or mismatched certificates are still inspected. Optional: probe_versions (TLS 1.0-1.3 support), STARTTLS for smtp/imap/pop3/ftp, client certificates.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in tlsInspectIn) (any, error) {
			host := strings.TrimSpace(in.Host)
			if after, ok := strings.CutPrefix(host, "https://"); ok {
				host = strings.SplitN(after, "/", 2)[0]
			}
			st := strings.ToLower(strings.TrimSpace(in.StartTLS))
			defPort := 443
			if st != "" {
				p, ok := starttlsPorts[st]
				if !ok {
					return nil, fmt.Errorf("unsupported starttls %q (use smtp, imap, pop3 or ftp)", in.StartTLS)
				}
				defPort = p
			}
			addr, err := targetAddr(host, in.Port, defPort)
			if err != nil {
				return nil, err
			}
			minV, err := netx.ParseTLSVersion(in.MinVersion)
			if err != nil {
				return nil, err
			}
			maxV, err := netx.ParseTLSVersion(in.MaxVersion)
			if err != nil {
				return nil, err
			}
			if minV != 0 && maxV != 0 && minV > maxV {
				return nil, fmt.Errorf("min_version is above max_version")
			}
			name := in.ServerName
			if name == "" {
				name = hostOnly(addr)
			}
			sni := name
			if ip, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
				sni = ip.String() // not sent as SNI, but verified against IP SANs
			}
			base, err := tlsx.Config(d.Files, in.TLSOptions, sni, nil)
			if err != nil {
				return nil, err
			}
			timeout := d.Cfg.Timeout(in.TimeoutSeconds)
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			dl := d.Guard.Dialer(in.AllowPrivate, timeout)
			res, err := netx.Inspect(ctx, netx.InspectRequest{
				Addr: addr, Dial: dl.DialContext, Base: base, ServerName: sni, ALPN: in.ALPN,
				MinVersion: minV, MaxVersion: maxV, StartTLS: st, Probe: in.ProbeVersions, IncludePEM: in.IncludePEM,
			})
			if err != nil {
				return nil, err
			}
			if in.InsecureSkipVerify {
				res.Warnings = append(res.Warnings, "insecure_skip_verify has no effect here: tls_inspect always completes the handshake and reports verification separately")
			}
			for _, c := range res.Chain[:min(1, len(res.Chain))] {
				switch {
				case c.Expired:
					res.Warnings = append(res.Warnings, "the leaf certificate has expired")
				case c.DaysUntilExpiry < 14:
					res.Warnings = append(res.Warnings, fmt.Sprintf("the leaf certificate expires in %d days", c.DaysUntilExpiry))
				}
			}
			return res, nil
		})
}
