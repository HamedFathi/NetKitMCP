package brokertools

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupMessaging, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerAMQP(s, d)
	registerKafka(s, d)
	registerSTOMP(s, d)
}

// maxBrokerPayload bounds a single message body held in memory (brokers
// need the whole body up front).
const maxBrokerPayload = 64 << 20

// payload resolves an optional payload into memory, bounded.
func payload(d *tools.Deps, p *types.Payload) ([]byte, string, *types.FileInfo, error) {
	if p.IsZero() {
		return nil, "", nil, nil
	}
	limit := d.Cfg.UploadBytes(0)
	if limit > maxBrokerPayload {
		limit = maxBrokerPayload
	}
	rp, err := p.Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, limit)
	if err != nil {
		return nil, "", nil, err
	}
	data, err := rp.Bytes(limit)
	if err != nil {
		return nil, "", nil, err
	}
	return data, rp.ContentType, rp.File, nil
}

// tlsConfig builds a client TLS config, merging mtls auth.
func tlsConfig(d *tools.Deps, opts types.TLSOptions, a *auth.Config, serverName string) (*tls.Config, error) {
	if a != nil {
		auth.ApplyTLS(a, &opts)
	}
	return tlsx.Config(d.Files, opts, serverName, nil)
}

// wantsTLS reports whether any TLS option was set explicitly.
func wantsTLS(opts types.TLSOptions, a *auth.Config) bool {
	return opts.InsecureSkipVerify || opts.CACert != "" || opts.ClientCert != "" || opts.ServerName != "" ||
		(a != nil && a.Kind() == "mtls")
}

// credentials returns user/password from the shared auth object.
func credentials(a *auth.Config) (string, string, error) {
	if a == nil || a.Kind() == "none" {
		return "", "", nil
	}
	if a.Kind() == "mtls" {
		return "", "", nil
	}
	u, p, ok := auth.UserPass(a)
	if !ok {
		return "", "", fmt.Errorf("auth type %q is not supported here (use basic, bearer or mtls)", a.Kind())
	}
	return u, p, nil
}

func insecureWarnings(opts types.TLSOptions) []string {
	if opts.InsecureSkipVerify {
		return []string{"TLS certificate verification is disabled (insecure_skip_verify=true)"}
	}
	return nil
}

func tlsInfo(cs *tls.ConnectionState, opts types.TLSOptions) *types.TLSInfo {
	return tlsx.Info(cs, opts.InsecureSkipVerify)
}

// encodeBody returns (data, encoding, message type) for a message body.
func encodeBody(body []byte, contentType string) (string, string, string) {
	data, enc := types.EncodeBody(body, contentType)
	typ := "text"
	if enc == "base64" {
		typ = "binary"
	}
	return data, enc, typ
}

func ms(t time.Time) float64 { return types.MS(time.Since(t)) }
