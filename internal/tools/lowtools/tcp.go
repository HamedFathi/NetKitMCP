package lowtools

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() {
	tools.RegisterGroup(tools.GroupLowLevel, func(s *mcp.Server, d *tools.Deps) {
		registerTCP(s, d)
		registerUDP(s, d)
		registerDNS(s, d)
		registerTLSInspect(s, d)
	})
}

type tcpIn struct {
	Host string `json:"host" jsonschema:"target hostname or IP (may include :port)"`
	Port int    `json:"port,omitempty" jsonschema:"target TCP port"`
	SendData
	File      string `json:"file,omitempty" jsonschema:"send this file (path inside an allowed read directory), streamed; instead of data"`
	HalfClose bool   `json:"half_close,omitempty" jsonschema:"close the write side after sending (signals EOF to the server)"`

	TLS  bool     `json:"tls,omitempty" jsonschema:"wrap the connection in TLS (SNI = server_name or host)"`
	ALPN []string `json:"alpn,omitempty" jsonschema:"TLS ALPN protocols to offer, e.g. [\"h2\",\"http/1.1\"]"`

	Delimiter          string  `json:"delimiter,omitempty" jsonschema:"stop reading once this text is received (escapes apply when escapes=true)"`
	DelimiterHex       string  `json:"delimiter_hex,omitempty" jsonschema:"stop reading once these bytes (hex) are received"`
	ReadBytes          int64   `json:"read_bytes,omitempty" jsonschema:"stop reading after this many bytes"`
	ReadTimeoutSeconds float64 `json:"read_timeout_seconds,omitempty" jsonschema:"stop when no data arrives for this many seconds (default 3 when no delimiter/read_bytes is set)"`
	NoRead             bool    `json:"no_read,omitempty" jsonschema:"only send; do not wait for a response"`
	MaxResponseBytes   int64   `json:"max_response_bytes,omitempty" jsonschema:"maximum received bytes returned (default 1 MiB)"`
	Output             string  `json:"output,omitempty" jsonschema:"how to return received data: auto (text if printable else base64), text, base64 or hex"`
	HexPreview         bool    `json:"hex_preview,omitempty" jsonschema:"also return a hexdump of the first 512 received bytes"`

	types.NetOptions
}

type tcpTiming struct {
	Connect   float64  `json:"connect"`
	TLS       float64  `json:"tls,omitempty"`
	FirstByte *float64 `json:"first_byte,omitempty"`
	Total     float64  `json:"total"`
}

type tcpOut struct {
	Address       string          `json:"address"`
	RemoteAddr    string          `json:"remote_addr"`
	LocalAddr     string          `json:"local_addr"`
	Data          string          `json:"data"`
	Encoding      string          `json:"encoding"`
	HexPreview    string          `json:"hex_preview,omitempty"`
	BytesSent     int64           `json:"bytes_sent"`
	BytesReceived int64           `json:"bytes_received"`
	EndedBy       string          `json:"ended_by"`
	Truncated     bool            `json:"truncated"`
	SendError     string          `json:"send_error,omitempty"`
	ReadError     string          `json:"read_error,omitempty"`
	File          *types.FileInfo `json:"file,omitempty"`
	TimingMS      tcpTiming       `json:"timing_ms"`
	TLS           *types.TLSInfo  `json:"tls,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
}

func registerTCP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "tcp_request", "Raw TCP request",
		"Open a raw TCP connection (optionally TLS) to host:port, send data (text with optional escapes, hex, base64, or a streamed file), "+
			"then read until a delimiter, a byte count, connection close, or read_timeout_seconds of silence. "+
			"Use it for line protocols (SMTP, Redis, memcached), banners and custom binary protocols. "+
			"Returns received data, bytes sent/received, ended_by, timing and TLS details. Subject to the SSRF guard and port allowlist.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in tcpIn) (any, error) {
			return runTCP(ctx, d, in)
		})
}

func runTCP(ctx context.Context, d *tools.Deps, in tcpIn) (any, error) {
	addr, err := targetAddr(in.Host, in.Port, 0)
	if err != nil {
		return nil, err
	}
	if in.File != "" && in.Data != "" {
		return nil, errorf("set either data or file, not both")
	}
	if in.Delimiter != "" && in.DelimiterHex != "" {
		return nil, errorf("set either delimiter or delimiter_hex, not both")
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dl := d.Guard.RawDialer(in.AllowPrivate, timeout)

	var delim []byte
	switch {
	case in.DelimiterHex != "":
		if delim, err = netx.ParseHex(in.DelimiterHex); err != nil {
			return nil, errorf("delimiter_hex: %v", err)
		}
	case in.Delimiter != "":
		if in.Escapes {
			if delim, err = netx.Unescape(in.Delimiter); err != nil {
				return nil, errorf("delimiter: %v", err)
			}
		} else {
			delim = []byte(in.Delimiter)
		}
	}

	out := &tcpOut{Address: addr}
	var send io.Reader
	var hr *fileio.HashingReader
	if in.File != "" {
		f, st, err := d.Files.OpenRead(in.File, d.Cfg.UploadBytes(0))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		hr = fileio.NewHashingReader(f)
		send = hr
		out.File = &types.FileInfo{Name: st.Name(), Path: f.Name(), SizeBytes: st.Size(), ContentType: fileio.DetectContentType(f.Name(), nil)}
	} else if in.Data != "" {
		b, err := in.SendData.resolve(d.Cfg.MaxInlineBase64Bytes)
		if err != nil {
			return nil, err
		}
		send = bytesReader(b)
	}

	var tlsCfg *tls.Config
	if in.TLS {
		tlsCfg, err = tlsx.Config(d.Files, in.TLSOptions, hostOnly(addr), in.ALPN)
		if err != nil {
			return nil, err
		}
		if in.InsecureSkipVerify {
			out.Warnings = append(out.Warnings, insecureWarning)
		}
	} else if len(in.ALPN) > 0 || in.ServerName != "" {
		out.Warnings = append(out.Warnings, "alpn/server_name are ignored because tls is false")
	}

	idle := time.Duration(in.ReadTimeoutSeconds * float64(time.Second))
	if idle <= 0 && len(delim) == 0 && in.ReadBytes <= 0 {
		idle = 3 * time.Second
	}
	maxBytes := d.Cfg.ResponseBytes(in.MaxResponseBytes)
	res, err := netx.TCPExchange(ctx, netx.TCPRequest{
		Addr: addr, Dial: dl.DialContext, TLS: tlsCfg, Send: send, HalfClose: in.HalfClose, NoRead: in.NoRead,
		Delimiter: delim, ReadBytes: in.ReadBytes, MaxBytes: maxBytes, Idle: idle,
	})
	if err != nil {
		return nil, err
	}
	out.Data, out.Encoding, err = encodeOutput(res.Data, in.Output)
	if err != nil {
		return nil, err
	}
	if in.HexPreview && len(res.Data) > 0 {
		out.HexPreview = netx.HexDump(res.Data, 512)
	}
	out.RemoteAddr, out.LocalAddr = res.RemoteAddr, res.LocalAddr
	out.BytesSent, out.BytesReceived = res.BytesSent, res.BytesReceived
	out.EndedBy, out.Truncated = res.EndedBy, res.Truncated
	out.SendError, out.ReadError = res.SendError, res.ReadError
	out.TimingMS = tcpTiming{Connect: res.ConnectMS, TLS: res.TLSMS, Total: res.TotalMS}
	if res.FirstByteMS >= 0 {
		fb := res.FirstByteMS
		out.TimingMS.FirstByte = &fb
	}
	if res.TLS != nil {
		out.TLS = tlsx.Info(res.TLS, in.InsecureSkipVerify)
	}
	if hr != nil {
		out.File.SHA256 = hr.SHA256()
		if hr.N() != out.File.SizeBytes {
			out.Warnings = append(out.Warnings, "file was not sent completely")
		}
	}
	if res.EndedBy == netx.EndedTimeout {
		out.Warnings = append(out.Warnings, "the overall timeout expired while reading; set delimiter, read_bytes or read_timeout_seconds to stop earlier")
	}
	return out, nil
}
