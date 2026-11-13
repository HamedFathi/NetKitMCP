package lowtools

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// SendData is an inline payload for raw socket tools.
type SendData struct {
	Data     string `json:"data,omitempty" jsonschema:"data to send, interpreted according to encoding"`
	Encoding string `json:"encoding,omitempty" jsonschema:"encoding of data: text (default), hex or base64"`
	Escapes  bool   `json:"escapes,omitempty" jsonschema:"interpret backslash escapes in text data and text delimiter (\\r \\n \\t \\0 \\xHH)"`
}

// resolve decodes the inline payload. maxBase64 bounds decoded binary input.
func (s SendData) resolve(maxBytes int64) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	switch strings.ToLower(strings.TrimSpace(s.Encoding)) {
	case "", "text", "utf8", "utf-8":
		if s.Escapes {
			b, err = netx.Unescape(s.Data)
		} else {
			b = []byte(s.Data)
		}
	case "hex":
		b, err = netx.ParseHex(s.Data)
	case "base64":
		b, err = types.DecodeBase64(strings.TrimSpace(s.Data))
	default:
		return nil, fmt.Errorf("unknown encoding %q (use text, hex or base64)", s.Encoding)
	}
	if err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("inline data is %d bytes, above the %d byte limit; use file instead", len(b), maxBytes)
	}
	return b, nil
}

// encodeOutput renders received bytes. mode: auto (default), text, base64, hex.
func encodeOutput(b []byte, mode string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		s, enc := types.EncodeBody(b, "")
		return s, enc, nil
	case "text":
		return strings.ToValidUTF8(string(b), "�"), "text", nil
	case "base64":
		return base64.StdEncoding.EncodeToString(b), "base64", nil
	case "hex":
		return hex.EncodeToString(b), "hex", nil
	}
	return "", "", fmt.Errorf("unknown output %q (use auto, text, base64 or hex)", mode)
}

// targetAddr builds host:port from a host (which may already carry a port)
// and a port.
func targetAddr(host string, port int, defPort int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("host is required")
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("host must be a hostname or IP address, not a URL: %q", host)
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if port != 0 {
			return "", fmt.Errorf("host %q already contains a port; drop port or the :port suffix", host)
		}
		if _, err := strconv.Atoi(p); err != nil {
			return "", fmt.Errorf("invalid port in %q", host)
		}
		return net.JoinHostPort(h, p), nil
	}
	if port == 0 {
		port = defPort
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("port is required (1-65535)")
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)), nil
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

const insecureWarning = "TLS certificate verification was skipped (insecure_skip_verify=true)"

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
