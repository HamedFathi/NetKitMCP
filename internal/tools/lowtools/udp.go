package lowtools

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type udpIn struct {
	Host string `json:"host" jsonschema:"target hostname or IP (may include :port)"`
	Port int    `json:"port,omitempty" jsonschema:"target UDP port"`
	SendData
	MaxResponses     int     `json:"max_responses,omitempty" jsonschema:"stop after this many reply datagrams (default 1, max 1000)"`
	WaitSeconds      float64 `json:"wait_seconds,omitempty" jsonschema:"how long to collect replies after sending (default 2)"`
	MaxResponseBytes int64   `json:"max_response_bytes,omitempty" jsonschema:"maximum total reply bytes returned (default 1 MiB)"`
	Output           string  `json:"output,omitempty" jsonschema:"how to return reply data: auto (text if printable else base64), text, base64 or hex"`
	HexPreview       bool    `json:"hex_preview,omitempty" jsonschema:"also return a hexdump of each reply (first 512 bytes)"`
	types.NetOptions
}

type udpReply struct {
	Seq        int     `json:"seq"`
	From       string  `json:"from"`
	SizeBytes  int     `json:"size_bytes"`
	Data       string  `json:"data"`
	Encoding   string  `json:"encoding"`
	HexPreview string  `json:"hex_preview,omitempty"`
	Truncated  bool    `json:"truncated,omitempty"`
	ElapsedMS  float64 `json:"elapsed_ms"`
}

type udpOut struct {
	Address    string     `json:"address"`
	RemoteAddr string     `json:"remote_addr"`
	LocalAddr  string     `json:"local_addr"`
	BytesSent  int        `json:"bytes_sent"`
	Responses  []udpReply `json:"responses"`
	EndedBy    string     `json:"ended_by"`
	Error      string     `json:"error,omitempty"`
	Truncated  bool       `json:"truncated"`
	TimingMS   struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
}

func registerUDP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "udp_request", "Raw UDP request",
		"Send one UDP datagram (text with optional escapes, hex or base64) to host:port and collect up to max_responses reply datagrams within wait_seconds. "+
			"Use it for UDP protocols such as NTP, SNMP, syslog, game or custom binary protocols. ended_by is max_responses or timeout "+
			"(no reply is normal for fire-and-forget protocols). Subject to the SSRF guard and port allowlist.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in udpIn) (any, error) {
			addr, err := targetAddr(in.Host, in.Port, 0)
			if err != nil {
				return nil, err
			}
			data, err := in.SendData.resolve(65507)
			if err != nil {
				return nil, err
			}
			timeout := d.Cfg.Timeout(in.TimeoutSeconds)
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			dl := d.Guard.RawDialer(in.AllowPrivate, timeout)
			wait := time.Duration(in.WaitSeconds * float64(time.Second))
			if wait <= 0 {
				wait = 2 * time.Second
			}
			maxResp := in.MaxResponses
			if maxResp <= 0 {
				maxResp = 1
			}
			maxResp = min(maxResp, 1000, d.Cfg.MaxMessages)
			res, err := netx.UDPExchange(ctx, netx.UDPRequest{
				Addr: addr, Dial: dl.DialContext, Data: data, MaxResponses: maxResp, Wait: wait,
				MaxBytes: d.Cfg.ResponseBytes(in.MaxResponseBytes),
			})
			if err != nil {
				return nil, err
			}
			out := &udpOut{Address: addr, RemoteAddr: res.RemoteAddr, LocalAddr: res.LocalAddr, BytesSent: res.BytesSent,
				Responses: []udpReply{}, EndedBy: res.EndedBy, Error: res.Error, Truncated: res.Truncated}
			out.TimingMS.Total = res.TotalMS
			for i, dg := range res.Responses {
				r := udpReply{Seq: i + 1, From: dg.From, SizeBytes: dg.Size, Truncated: dg.Truncated, ElapsedMS: dg.ElapsedMS}
				if r.Data, r.Encoding, err = encodeOutput(dg.Data, in.Output); err != nil {
					return nil, err
				}
				if in.HexPreview && len(dg.Data) > 0 {
					r.HexPreview = netx.HexDump(dg.Data, 512)
				}
				out.Responses = append(out.Responses, r)
			}
			return out, nil
		})
}
