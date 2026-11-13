package lowtools

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type dnsIn struct {
	Name             string `json:"name" jsonschema:"domain name to query; an IP address with type PTR (or no type) does a reverse lookup"`
	Type             string `json:"type,omitempty" jsonschema:"record type: A (default), AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, DS, DNSKEY, RRSIG, HTTPS, SVCB, NAPTR, TLSA, ANY, TYPEnnn ..."`
	Class            string `json:"class,omitempty" jsonschema:"query class: IN (default), CH, HS"`
	Server           string `json:"server,omitempty" jsonschema:"resolver: host[:port] for udp/tcp/dot (default port 53/853), an https URL for doh. Default: the system resolver (1.1.1.1 where unknown)"`
	Transport        string `json:"transport,omitempty" jsonschema:"udp (default; retries over TCP when truncated), tcp, dot (DNS over TLS) or doh (DNS over HTTPS)"`
	DoHMethod        string `json:"doh_method,omitempty" jsonschema:"doh only: POST (default) or GET"`
	RecursionDesired *bool  `json:"rd,omitempty" jsonschema:"set the RD (recursion desired) flag (default true)"`
	CheckingDisabled bool   `json:"cd,omitempty" jsonschema:"set the CD (checking disabled) flag"`
	AuthenticData    bool   `json:"ad,omitempty" jsonschema:"set the AD flag in the query (ask for the authenticated-data bit)"`
	DNSSEC           bool   `json:"dnssec,omitempty" jsonschema:"set the EDNS DO bit to request DNSSEC records (RRSIG, ...)"`
	NoEDNS           bool   `json:"no_edns,omitempty" jsonschema:"send a plain query without an EDNS OPT record"`
	EDNSBufferSize   int    `json:"edns_buffer_size,omitempty" jsonschema:"EDNS UDP buffer size (default 1232)"`
	ClientSubnet     string `json:"client_subnet,omitempty" jsonschema:"EDNS client subnet (ECS), e.g. 203.0.113.0/24"`
	NoTCPFallback    bool   `json:"no_tcp_fallback,omitempty" jsonschema:"udp: return the truncated reply instead of retrying over TCP"`
	types.NetOptions
}

type dnsQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type dnsOut struct {
	Question    dnsQuestion    `json:"question"`
	Server      string         `json:"server"`
	Transport   string         `json:"transport"`
	ID          uint16         `json:"id"`
	Opcode      string         `json:"opcode"`
	Rcode       string         `json:"rcode"`
	Flags       []string       `json:"flags"`
	Answer      []netx.Record  `json:"answer"`
	Authority   []netx.Record  `json:"authority"`
	Additional  []netx.Record  `json:"additional"`
	EDNS        *netx.EDNSInfo `json:"edns,omitempty"`
	TCPFallback bool           `json:"tcp_fallback,omitempty"`
	Truncated   bool           `json:"truncated,omitempty"`
	SizeBytes   int            `json:"size_bytes"`
	HTTPStatus  int            `json:"http_status,omitempty"`
	TimingMS    struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Text     string   `json:"text"`
	Warnings []string `json:"warnings,omitempty"`
}

func registerDNS(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "dns_query", "DNS query",
		"Resolve any DNS record type (A, AAAA, MX, TXT, SRV, CAA, DNSKEY, HTTPS, PTR for IPs, ANY ...) against a chosen resolver over "+
			"udp (TCP retry on truncation), tcp, dot (DNS over TLS) or doh (DNS over HTTPS, RFC 8484). Flags: rd, cd, ad, dnssec (DO bit), "+
			"EDNS buffer size and client subnet. Returns rcode, flags, structured answer/authority/additional records and dig-style text. "+
			"The resolver address is subject to the SSRF guard and port allowlist.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in dnsIn) (any, error) {
			return runDNS(ctx, d, in)
		})
}

func runDNS(ctx context.Context, d *tools.Deps, in dnsIn) (any, error) {
	name := strings.TrimSpace(in.Name)
	qtype, err := netx.ParseType(in.Type)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Type) == "" {
		if _, err := netip.ParseAddr(name); err == nil {
			qtype = dns.TypePTR
		}
	}
	qclass, err := netx.ParseClass(in.Class)
	if err != nil {
		return nil, err
	}
	transport := strings.ToLower(strings.TrimSpace(in.Transport))
	switch transport {
	case "", "udp":
		transport = netx.DNSUDP
	case "tcp":
	case "dot", "tls", "tcp-tls":
		transport = netx.DNSDoT
	case "doh", "https":
		transport = netx.DNSDoH
	default:
		return nil, fmt.Errorf("unknown transport %q (use udp, tcp, dot or doh)", in.Transport)
	}
	var warnings []string
	if in.InsecureSkipVerify && (transport == netx.DNSDoT || transport == netx.DNSDoH) {
		warnings = append(warnings, insecureWarning)
	}
	server := strings.TrimSpace(in.Server)
	switch transport {
	case netx.DNSDoH:
		if server == "" {
			server = netx.DefaultDoHServer
		} else if !strings.Contains(server, "://") {
			server = "https://" + server + "/dns-query"
		}
	case netx.DNSDoT:
		if server == "" {
			server = netx.DefaultDoTServer
		}
		server = netx.JoinHostPort(server, 853)
	default:
		if server == "" {
			var note string
			server, note = netx.SystemServer()
			if note != "" {
				warnings = append(warnings, note)
			}
		}
		server = netx.JoinHostPort(server, 53)
	}

	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r := &netx.DNSRequest{
		Name: name, Type: qtype, Class: qclass, Transport: transport, Server: server,
		RD: types.BoolDefault(in.RecursionDesired, true), CD: in.CheckingDisabled, AD: in.AuthenticData, DO: in.DNSSEC,
		NoEDNS: in.NoEDNS, ECS: in.ClientSubnet, NoTCPFallback: in.NoTCPFallback, Timeout: timeout,
		DoHGET: strings.EqualFold(in.DoHMethod, "GET"),
	}
	if in.EDNSBufferSize < 0 || in.EDNSBufferSize > 65535 {
		return nil, fmt.Errorf("edns_buffer_size must be between 512 and 65535")
	}
	r.EDNSSize = uint16(in.EDNSBufferSize)
	switch transport {
	case netx.DNSDoH:
		hc, err := d.NewHTTPClient(types.HTTPOptions{NetOptions: in.NetOptions}, nil)
		if err != nil {
			return nil, err
		}
		defer hc.Close()
		r.HTTP = hc.Client
	default:
		r.Dial = d.Guard.RawDialer(in.AllowPrivate, timeout).DialContext
		if transport == netx.DNSDoT {
			r.TLS, err = tlsx.Config(d.Files, in.TLSOptions, hostOnly(server), nil)
			if err != nil {
				return nil, err
			}
		}
	}
	q, err := netx.BuildQuery(r)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	res, err := netx.Exchange(ctx, r, q)
	if err != nil {
		return nil, err
	}
	m := res.Reply
	out := &dnsOut{
		Question:    dnsQuestion{Name: q.Question[0].Name, Type: dns.Type(qtype).String(), Class: dns.Class(qclass).String()},
		Server:      res.Server,
		Transport:   res.Transport,
		ID:          m.Id,
		Opcode:      dns.OpcodeToString[m.Opcode],
		Rcode:       netx.RcodeName(m),
		Flags:       netx.Flags(m),
		Answer:      netx.Records(m.Answer),
		Authority:   netx.Records(m.Ns),
		Additional:  netx.Records(m.Extra),
		EDNS:        netx.EDNS(m),
		TCPFallback: res.TCPFallback,
		Truncated:   m.Truncated,
		SizeBytes:   res.ReplySize,
		HTTPStatus:  res.HTTPStatus,
		Warnings:    warnings,
	}
	out.TimingMS.Total = netx.MS(time.Since(start))
	if res.TCPFallback {
		out.Warnings = append(out.Warnings, "the UDP reply was truncated; the query was retried over TCP")
	} else if m.Truncated {
		out.Warnings = append(out.Warnings, "the reply is truncated (TC flag); retry with transport=tcp for the full answer")
	}
	out.Text = m.String() + fmt.Sprintf(";; Query time: %d msec\n;; SERVER: %s (%s)\n;; WHEN: %s\n;; MSG SIZE  rcvd: %d\n",
		res.RTT.Milliseconds(), res.Server, res.Transport, time.Now().UTC().Format(time.RFC1123), res.ReplySize)
	return out, nil
}
