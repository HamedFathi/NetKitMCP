package netx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS transports.
const (
	DNSUDP = "udp"
	DNSTCP = "tcp"
	DNSDoT = "dot"
	DNSDoH = "doh"
)

// Default public resolvers used when no system resolver is known.
const (
	FallbackDNSServer = "1.1.1.1:53"
	DefaultDoTServer  = "1.1.1.1:853"
	DefaultDoHServer  = "https://cloudflare-dns.com/dns-query"
)

// DNSRequest describes one DNS query.
type DNSRequest struct {
	Name      string
	Type      uint16
	Class     uint16
	Transport string // udp (default), tcp, dot, doh
	Server    string // host:port, or URL for doh

	RD, CD, AD, DO bool
	NoEDNS         bool
	EDNSSize       uint16 // default 1232
	ECS            string // EDNS client subnet, e.g. "203.0.113.0/24"
	NoTCPFallback  bool

	Dial    DialFunc     // udp/tcp/dot
	TLS     *tls.Config  // dot
	HTTP    *http.Client // doh
	DoHGET  bool
	Timeout time.Duration
}

// DNSResult is the outcome of a DNS exchange.
type DNSResult struct {
	Query       *dns.Msg
	Reply       *dns.Msg
	RTT         time.Duration
	TCPFallback bool
	Server      string
	Transport   string
	HTTPStatus  int
	ReplySize   int
}

// ParseType parses a record type name ("A", "aaaa", "TYPE65") or number.
func ParseType(s string) (uint16, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return dns.TypeA, nil
	}
	if t, ok := dns.StringToType[s]; ok {
		return t, nil
	}
	if strings.HasPrefix(s, "TYPE") {
		s = s[4:]
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown DNS record type %q", s)
}

// ParseClass parses a class name ("IN", "CH") or number.
func ParseClass(s string) (uint16, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return dns.ClassINET, nil
	}
	if c, ok := dns.StringToClass[s]; ok {
		return c, nil
	}
	if strings.HasPrefix(s, "CLASS") {
		s = s[5:]
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown DNS class %q", s)
}

// QueryName returns the FQDN to query. For PTR queries an IP address is
// turned into its reverse name (in-addr.arpa / ip6.arpa).
func QueryName(name string, qtype uint16) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name is required")
	}
	if qtype == dns.TypePTR {
		if _, err := netip.ParseAddr(name); err == nil {
			return dns.ReverseAddr(name)
		}
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", fmt.Errorf("invalid domain name %q", name)
	}
	return dns.Fqdn(name), nil
}

// SystemServer returns the first nameserver from /etc/resolv.conf, or the
// fallback resolver plus a note explaining why.
func SystemServer() (string, string) {
	if runtime.GOOS != "windows" {
		if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
			port := cc.Port
			if port == "" {
				port = "53"
			}
			return net.JoinHostPort(cc.Servers[0], port), ""
		}
		return FallbackDNSServer, "no nameserver found in /etc/resolv.conf; using " + FallbackDNSServer
	}
	return FallbackDNSServer, "the system resolver cannot be read on Windows; using " + FallbackDNSServer + " (set server to query a specific resolver)"
}

// BuildQuery builds the query message.
func BuildQuery(r *DNSRequest) (*dns.Msg, error) {
	name, err := QueryName(r.Name, r.Type)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{{Name: name, Qtype: r.Type, Qclass: r.Class}}
	if r.Class == 0 {
		m.Question[0].Qclass = dns.ClassINET
	}
	m.Opcode = dns.OpcodeQuery
	m.RecursionDesired = r.RD
	m.CheckingDisabled = r.CD
	m.AuthenticatedData = r.AD
	if r.Transport == DNSDoH {
		m.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	}
	if r.NoEDNS {
		if r.DO || r.ECS != "" {
			return nil, errors.New("dnssec (DO) and ECS need EDNS; do not set no_edns")
		}
		return m, nil
	}
	size := r.EDNSSize
	if size == 0 {
		size = 1232
	}
	m.SetEdns0(size, r.DO)
	if r.ECS != "" {
		opt := m.IsEdns0()
		p, err := netip.ParsePrefix(r.ECS)
		if err != nil {
			a, aerr := netip.ParseAddr(r.ECS)
			if aerr != nil {
				return nil, fmt.Errorf("invalid ecs subnet %q (use e.g. 203.0.113.0/24)", r.ECS)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(p.Bits()), Address: net.IP(p.Addr().AsSlice())}
		if p.Addr().Is4() {
			sub.Family = 1
		} else {
			sub.Family = 2
		}
		opt.Option = append(opt.Option, sub)
	}
	return m, nil
}

// Exchange sends the query over the requested transport.
func Exchange(ctx context.Context, r *DNSRequest, q *dns.Msg) (*DNSResult, error) {
	if r.Timeout <= 0 {
		r.Timeout = 10 * time.Second
	}
	res := &DNSResult{Query: q, Server: r.Server, Transport: r.Transport}
	switch r.Transport {
	case "", DNSUDP:
		res.Transport = DNSUDP
		reply, rtt, size, err := exchangeConn(ctx, r, "udp", q)
		if err != nil {
			return nil, err
		}
		res.Reply, res.RTT, res.ReplySize = reply, rtt, size
		if reply.Truncated && !r.NoTCPFallback {
			reply2, rtt2, size2, err := exchangeConn(ctx, r, "tcp", q)
			if err != nil {
				return nil, fmt.Errorf("response truncated over UDP and the TCP retry failed: %w", err)
			}
			res.Reply, res.RTT, res.ReplySize = reply2, rtt+rtt2, size2
			res.TCPFallback = true
		}
	case DNSTCP:
		reply, rtt, size, err := exchangeConn(ctx, r, "tcp", q)
		if err != nil {
			return nil, err
		}
		res.Reply, res.RTT, res.ReplySize = reply, rtt, size
	case DNSDoT:
		reply, rtt, size, err := exchangeConn(ctx, r, "tcp-tls", q)
		if err != nil {
			return nil, err
		}
		res.Reply, res.RTT, res.ReplySize = reply, rtt, size
	case DNSDoH:
		if err := exchangeDoH(ctx, r, q, res); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown transport %q (use udp, tcp, dot or doh)", r.Transport)
	}
	return res, nil
}

func exchangeConn(ctx context.Context, r *DNSRequest, network string, q *dns.Msg) (*dns.Msg, time.Duration, int, error) {
	if r.Dial == nil {
		return nil, 0, 0, errors.New("netx: no dialer")
	}
	dialNet := network
	if network == "tcp-tls" {
		dialNet = "tcp"
	}
	t0 := time.Now()
	c, err := r.Dial(ctx, dialNet, r.Server)
	if err != nil {
		return nil, 0, 0, err
	}
	defer c.Close()
	if network == "tcp-tls" {
		tc := tls.Client(c, r.TLS)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, 0, 0, fmt.Errorf("DoT TLS handshake with %s: %w", r.Server, err)
		}
		c = tc
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	cl := &dns.Client{Net: network, Timeout: r.Timeout}
	co := &dns.Conn{Conn: c}
	reply, _, err := cl.ExchangeWithConnContext(ctx, q, co)
	rtt := time.Since(t0)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, rtt, 0, fmt.Errorf("no DNS reply from %s over %s within the timeout", r.Server, network)
		}
		return nil, rtt, 0, fmt.Errorf("DNS exchange with %s over %s: %w", r.Server, network, err)
	}
	return reply, rtt, reply.Len(), nil
}

func exchangeDoH(ctx context.Context, r *DNSRequest, q *dns.Msg, res *DNSResult) error {
	if r.HTTP == nil {
		return errors.New("netx: no HTTP client for DoH")
	}
	u, err := url.Parse(r.Server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("DoH server must be an http(s) URL such as %s, got %q", DefaultDoHServer, r.Server)
	}
	packed, err := q.Pack()
	if err != nil {
		return fmt.Errorf("pack query: %w", err)
	}
	var req *http.Request
	if r.DoHGET {
		qs := u.Query()
		qs.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
		u.RawQuery = qs.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(packed))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	t0 := time.Now()
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("DoH request to %s: %w", r.Server, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	res.RTT = time.Since(t0)
	res.HTTPStatus = resp.StatusCode
	if err != nil {
		return fmt.Errorf("DoH read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("DoH server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(snippet))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/dns-message") {
		return fmt.Errorf("DoH server returned Content-Type %q, expected application/dns-message", ct)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return fmt.Errorf("DoH: invalid DNS message: %w", err)
	}
	res.Reply = reply
	res.ReplySize = len(body)
	return nil
}

// Record is a resource record in structured form.
type Record struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Class  string         `json:"class"`
	TTL    uint32         `json:"ttl"`
	Data   string         `json:"data"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Records converts resource records, skipping OPT pseudo-records.
func Records(rrs []dns.RR) []Record {
	out := []Record{}
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		h := rr.Header()
		data := strings.TrimPrefix(rr.String(), h.String())
		out = append(out, Record{
			Name:   h.Name,
			Type:   dns.Type(h.Rrtype).String(),
			Class:  dns.Class(h.Class).String(),
			TTL:    h.Ttl,
			Data:   strings.TrimSpace(data),
			Fields: rrFields(rr),
		})
	}
	return out
}

func rrFields(rr dns.RR) map[string]any {
	switch v := rr.(type) {
	case *dns.A:
		return map[string]any{"address": v.A.String()}
	case *dns.AAAA:
		return map[string]any{"address": v.AAAA.String()}
	case *dns.CNAME:
		return map[string]any{"target": v.Target}
	case *dns.DNAME:
		return map[string]any{"target": v.Target}
	case *dns.NS:
		return map[string]any{"ns": v.Ns}
	case *dns.PTR:
		return map[string]any{"ptr": v.Ptr}
	case *dns.MX:
		return map[string]any{"preference": v.Preference, "exchange": v.Mx}
	case *dns.TXT:
		return map[string]any{"txt": v.Txt, "joined": strings.Join(v.Txt, "")}
	case *dns.SPF:
		return map[string]any{"txt": v.Txt}
	case *dns.SOA:
		return map[string]any{"mname": v.Ns, "rname": v.Mbox, "serial": v.Serial, "refresh": v.Refresh,
			"retry": v.Retry, "expire": v.Expire, "minimum": v.Minttl}
	case *dns.SRV:
		return map[string]any{"priority": v.Priority, "weight": v.Weight, "port": v.Port, "target": v.Target}
	case *dns.CAA:
		return map[string]any{"flag": v.Flag, "tag": v.Tag, "value": v.Value}
	case *dns.DS:
		return map[string]any{"key_tag": v.KeyTag, "algorithm": algName(v.Algorithm), "digest_type": v.DigestType, "digest": v.Digest}
	case *dns.DNSKEY:
		return map[string]any{"flags": v.Flags, "protocol": v.Protocol, "algorithm": algName(v.Algorithm),
			"key_tag": v.KeyTag(), "public_key": v.PublicKey, "sep": v.Flags&dns.SEP != 0}
	case *dns.RRSIG:
		return map[string]any{"type_covered": dns.Type(v.TypeCovered).String(), "algorithm": algName(v.Algorithm),
			"labels": v.Labels, "original_ttl": v.OrigTtl,
			"expiration": dns.TimeToString(v.Expiration), "inception": dns.TimeToString(v.Inception),
			"key_tag": v.KeyTag, "signer_name": v.SignerName}
	case *dns.NSEC:
		return map[string]any{"next_domain": v.NextDomain, "types": typeNames(v.TypeBitMap)}
	case *dns.NSEC3:
		return map[string]any{"hash": v.Hash, "flags": v.Flags, "iterations": v.Iterations, "salt": v.Salt,
			"next_domain": v.NextDomain, "types": typeNames(v.TypeBitMap)}
	case *dns.NAPTR:
		return map[string]any{"order": v.Order, "preference": v.Preference, "flags": v.Flags, "service": v.Service,
			"regexp": v.Regexp, "replacement": v.Replacement}
	case *dns.TLSA:
		return map[string]any{"usage": v.Usage, "selector": v.Selector, "matching_type": v.MatchingType, "certificate": v.Certificate}
	case *dns.SSHFP:
		return map[string]any{"algorithm": v.Algorithm, "type": v.Type, "fingerprint": v.FingerPrint}
	case *dns.HTTPS:
		return svcbFields(&v.SVCB)
	case *dns.SVCB:
		return svcbFields(v)
	case *dns.HINFO:
		return map[string]any{"cpu": v.Cpu, "os": v.Os}
	case *dns.RFC3597:
		return map[string]any{"rdata_hex": v.Rdata}
	}
	return nil
}

func svcbFields(v *dns.SVCB) map[string]any {
	params := map[string]string{}
	for _, kv := range v.Value {
		params[kv.Key().String()] = kv.String()
	}
	mode := "service"
	if v.Priority == 0 {
		mode = "alias"
	}
	return map[string]any{"priority": v.Priority, "target": v.Target, "mode": mode, "params": params}
}

func algName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return strconv.Itoa(int(a))
}

func typeNames(ts []uint16) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, dns.Type(t).String())
	}
	return out
}

// EDNSInfo describes the OPT record of a message (nil when absent).
type EDNSInfo struct {
	Version       uint8    `json:"version"`
	UDPSize       uint16   `json:"udp_size"`
	DO            bool     `json:"do"`
	ExtendedRcode string   `json:"extended_rcode,omitempty"`
	ClientSubnet  string   `json:"client_subnet,omitempty"`
	NSID          string   `json:"nsid,omitempty"`
	Cookie        string   `json:"cookie,omitempty"`
	ExtendedError string   `json:"extended_error,omitempty"`
	Options       []string `json:"options,omitempty"`
}

// EDNS extracts EDNS information.
func EDNS(m *dns.Msg) *EDNSInfo {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	info := &EDNSInfo{Version: opt.Version(), UDPSize: opt.UDPSize(), DO: opt.Do()}
	for _, o := range opt.Option {
		switch v := o.(type) {
		case *dns.EDNS0_SUBNET:
			info.ClientSubnet = fmt.Sprintf("%s/%d (scope /%d)", v.Address, v.SourceNetmask, v.SourceScope)
		case *dns.EDNS0_NSID:
			if b, err := hex.DecodeString(v.Nsid); err == nil {
				info.NSID = string(b)
			} else {
				info.NSID = v.Nsid
			}
		case *dns.EDNS0_COOKIE:
			info.Cookie = v.Cookie
		case *dns.EDNS0_EDE:
			info.ExtendedError = strings.TrimSpace(v.String())
		default:
			info.Options = append(info.Options, strings.TrimSpace(o.String()))
		}
	}
	return info
}

// Flags lists the header flags set on a message (dig style).
func Flags(m *dns.Msg) []string {
	var f []string
	if m.Response {
		f = append(f, "qr")
	}
	if m.Authoritative {
		f = append(f, "aa")
	}
	if m.Truncated {
		f = append(f, "tc")
	}
	if m.RecursionDesired {
		f = append(f, "rd")
	}
	if m.RecursionAvailable {
		f = append(f, "ra")
	}
	if m.AuthenticatedData {
		f = append(f, "ad")
	}
	if m.CheckingDisabled {
		f = append(f, "cd")
	}
	if f == nil {
		f = []string{}
	}
	return f
}

// RcodeName returns the textual rcode including the EDNS extended bits.
func RcodeName(m *dns.Msg) string {
	if s, ok := dns.RcodeToString[m.Rcode]; ok {
		return s
	}
	return strconv.Itoa(m.Rcode)
}
