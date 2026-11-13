package lowtools_test

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// answer is the test zone shared by every DNS transport.
func answer(req *dns.Msg, udp bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = req.RecursionDesired
	q := req.Question[0]
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		return r
	}
	switch {
	case q.Name == "example.test." && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, rr("example.test. 300 IN A 192.0.2.1"), rr("example.test. 300 IN A 192.0.2.2"))
	case q.Name == "example.test." && q.Qtype == dns.TypeMX:
		m.Answer = append(m.Answer, rr("example.test. 300 IN MX 10 mail.example.test."))
		m.Extra = append(m.Extra, rr("mail.example.test. 300 IN A 192.0.2.25"))
	case q.Name == "example.test." && q.Qtype == dns.TypeCAA:
		m.Answer = append(m.Answer, rr(`example.test. 300 IN CAA 0 issue "letsencrypt.org"`))
	case q.Name == "example.test." && q.Qtype == dns.TypeHTTPS:
		m.Answer = append(m.Answer, rr(`example.test. 300 IN HTTPS 1 . alpn="h2,h3" port=443`))
	case q.Name == "_sip._tcp.example.test." && q.Qtype == dns.TypeSRV:
		m.Answer = append(m.Answer, rr("_sip._tcp.example.test. 60 IN SRV 10 20 5060 sip.example.test."))
	case q.Name == "1.2.0.192.in-addr.arpa." && q.Qtype == dns.TypePTR:
		m.Answer = append(m.Answer, rr("1.2.0.192.in-addr.arpa. 300 IN PTR example.test."))
	case q.Name == "big.example.test." && q.Qtype == dns.TypeTXT:
		for i := 0; i < 40; i++ {
			m.Answer = append(m.Answer, rr(fmt.Sprintf(`big.example.test. 60 IN TXT "record-%02d %s"`, i, strings.Repeat("x", 60))))
		}
	default:
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, rr("example.test. 300 IN SOA ns.example.test. admin.example.test. 2026111001 7200 3600 1209600 300"))
	}
	if opt := req.IsEdns0(); opt != nil {
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(1232)
		o.SetDo(opt.Do())
		for _, e := range opt.Option {
			if s, ok := e.(*dns.EDNS0_SUBNET); ok {
				s.SourceScope = s.SourceNetmask
				o.Option = append(o.Option, s)
			}
		}
		m.Extra = append(m.Extra, o)
	}
	if udp {
		size := 512
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		m.Truncate(size)
	}
	return m
}

type dnsCounts struct{ udp, tcp atomic.Int32 }

// dnsServer serves the test zone on UDP and TCP on the same loopback port.
func dnsServer(t *testing.T) (string, *dnsCounts) {
	t.Helper()
	counts := &dnsCounts{}
	var pc net.PacketConn
	var ln net.Listener
	// Bind TCP first: on Windows, ephemeral UDP ports often fall inside TCP
	// port ranges reserved by Hyper-V, which TCP ephemeral allocation avoids.
	for i := 0; i < 100; i++ {
		var err error
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		pc, err = net.ListenPacket("udp", ln.Addr().String())
		if err == nil {
			break
		}
		ln.Close()
		pc, ln = nil, nil
	}
	if ln == nil || pc == nil {
		t.Fatal("could not bind UDP and TCP on the same port")
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		udp := w.RemoteAddr().Network() == "udp"
		if udp {
			counts.udp.Add(1)
		} else {
			counts.tcp.Add(1)
		}
		w.WriteMsg(answer(req, udp))
	})
	us := &dns.Server{PacketConn: pc, Handler: h}
	ts := &dns.Server{Listener: ln, Handler: h}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	t.Cleanup(func() { us.Shutdown(); ts.Shutdown() })
	return pc.LocalAddr().String(), counts
}

func records(t *testing.T, r *tooltest.Result, section string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, v := range r.Data[section].([]any) {
		out = append(out, v.(map[string]any))
	}
	return out
}

func TestDNSUDPRecordTypes(t *testing.T) {
	server, counts := dnsServer(t)
	h := tooltest.New(t, "lowlevel")

	r := h.MustOK("dns_query", map[string]any{"name": "example.test", "server": server})
	ans := records(t, r, "answer")
	if r.Data["rcode"] != "NOERROR" || len(ans) != 2 || ans[0]["type"] != "A" || ans[0]["fields"].(map[string]any)["address"] != "192.0.2.1" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	if r.Data["transport"] != "udp" || !strings.Contains(r.Data["text"].(string), "ANSWER SECTION") {
		t.Fatalf("unexpected transport/text: %s", r.Raw)
	}
	flags := fmt.Sprint(r.Data["flags"])
	if !strings.Contains(flags, "qr") || !strings.Contains(flags, "aa") || !strings.Contains(flags, "rd") {
		t.Fatalf("flags: %v", flags)
	}

	r = h.MustOK("dns_query", map[string]any{"name": "example.test", "type": "mx", "server": server})
	mx := records(t, r, "answer")[0]["fields"].(map[string]any)
	if num(mx["preference"]) != 10 || mx["exchange"] != "mail.example.test." || len(records(t, r, "additional")) != 1 {
		t.Fatalf("mx: %s", r.Raw)
	}

	r = h.MustOK("dns_query", map[string]any{"name": "_sip._tcp.example.test", "type": "SRV", "server": server})
	srv := records(t, r, "answer")[0]["fields"].(map[string]any)
	if num(srv["port"]) != 5060 || srv["target"] != "sip.example.test." {
		t.Fatalf("srv: %s", r.Raw)
	}

	r = h.MustOK("dns_query", map[string]any{"name": "example.test", "type": "CAA", "server": server})
	if caa := records(t, r, "answer")[0]["fields"].(map[string]any); caa["tag"] != "issue" || caa["value"] != "letsencrypt.org" {
		t.Fatalf("caa: %s", r.Raw)
	}

	r = h.MustOK("dns_query", map[string]any{"name": "example.test", "type": "HTTPS", "server": server})
	https := records(t, r, "answer")[0]["fields"].(map[string]any)
	if https["params"].(map[string]any)["alpn"] != "h2,h3" {
		t.Fatalf("https: %s", r.Raw)
	}

	// PTR from an IP, with type omitted.
	r = h.MustOK("dns_query", map[string]any{"name": "192.0.2.1", "server": server})
	if q := r.Data["question"].(map[string]any); q["name"] != "1.2.0.192.in-addr.arpa." || q["type"] != "PTR" {
		t.Fatalf("ptr question: %s", r.Raw)
	}
	if records(t, r, "answer")[0]["fields"].(map[string]any)["ptr"] != "example.test." {
		t.Fatalf("ptr: %s", r.Raw)
	}

	// NXDOMAIN is a result, not a tool error.
	r = h.MustOK("dns_query", map[string]any{"name": "missing.example.test", "server": server, "dnssec": true, "client_subnet": "203.0.113.7/24"})
	if r.Data["rcode"] != "NXDOMAIN" || len(records(t, r, "authority")) != 1 {
		t.Fatalf("nxdomain: %s", r.Raw)
	}
	edns := r.Data["edns"].(map[string]any)
	if edns["do"] != true || !strings.HasPrefix(edns["client_subnet"].(string), "203.0.113.0/24") {
		t.Fatalf("edns: %v", edns)
	}
	if counts.tcp.Load() != 0 {
		t.Fatalf("unexpected TCP queries")
	}
}

func TestDNSTruncationFallbackAndTCP(t *testing.T) {
	server, counts := dnsServer(t)
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("dns_query", map[string]any{"name": "big.example.test", "type": "TXT", "server": server})
	if r.Data["tcp_fallback"] != true || len(records(t, r, "answer")) != 40 {
		t.Fatalf("fallback: tcp_fallback=%v answers=%d", r.Data["tcp_fallback"], len(records(t, r, "answer")))
	}
	if counts.udp.Load() != 1 || counts.tcp.Load() != 1 {
		t.Fatalf("counts udp=%d tcp=%d", counts.udp.Load(), counts.tcp.Load())
	}
	r = h.MustOK("dns_query", map[string]any{"name": "big.example.test", "type": "TXT", "server": server, "no_tcp_fallback": true})
	if r.Data["truncated"] != true || r.Data["tcp_fallback"] == true {
		t.Fatalf("no fallback: %s", r.Raw)
	}
	r = h.MustOK("dns_query", map[string]any{"name": "example.test", "server": server, "transport": "tcp"})
	if r.Data["transport"] != "tcp" || len(records(t, r, "answer")) != 2 {
		t.Fatalf("tcp: %s", r.Raw)
	}
}

func TestDNSOverTLS(t *testing.T) {
	ca := newCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		w.WriteMsg(answer(req, false))
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("dns_query", map[string]any{"name": "example.test", "server": ln.Addr().String(), "transport": "dot",
		"ca_cert": ca.PEM, "server_name": "localhost"})
	if r.Data["transport"] != "dot" || len(records(t, r, "answer")) != 2 {
		t.Fatalf("dot: %s", r.Raw)
	}
	h.MustFail("dns_query", map[string]any{"name": "example.test", "server": ln.Addr().String(), "transport": "dot"}, "certificate")
}

func TestDNSOverHTTPS(t *testing.T) {
	var gets, posts atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		switch r.Method {
		case http.MethodPost:
			posts.Add(1)
			if r.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
				return
			}
			raw, _ = io.ReadAll(r.Body)
		case http.MethodGet:
			gets.Add(1)
			var err error
			raw, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if err != nil {
				http.Error(w, "bad dns param", http.StatusBadRequest)
				return
			}
		}
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil || req.Id != 0 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		out, _ := answer(req, false).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	t.Cleanup(ts.Close)

	h := tooltest.New(t, "lowlevel")
	url := ts.URL + "/dns-query"
	r := h.MustOK("dns_query", map[string]any{"name": "example.test", "type": "MX", "server": url, "transport": "doh", "insecure_skip_verify": true})
	if r.Data["transport"] != "doh" || num(r.Data["http_status"]) != 200 || len(records(t, r, "answer")) != 1 {
		t.Fatalf("doh: %s", r.Raw)
	}
	if !strings.Contains(fmt.Sprint(r.Data["warnings"]), "insecure_skip_verify") {
		t.Fatalf("missing insecure warning: %s", r.Raw)
	}
	h.MustOK("dns_query", map[string]any{"name": "example.test", "server": url, "transport": "doh", "doh_method": "GET", "insecure_skip_verify": true})
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
	// Untrusted certificate without insecure_skip_verify.
	h.MustFail("dns_query", map[string]any{"name": "example.test", "server": url, "transport": "doh"}, "certificate")
	// DoH goes through the guarded HTTP client.
	hg := tooltest.New(t, "lowlevel", tooltest.WithPrivateMode(config.PrivateOptIn))
	hg.MustFail("dns_query", map[string]any{"name": "example.test", "server": url, "transport": "doh", "insecure_skip_verify": true}, "allow_private")
}

func TestDNSGuardAndValidation(t *testing.T) {
	server, _ := dnsServer(t)
	_, port := splitAddr(t, server)
	h := tooltest.New(t, "lowlevel", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("dns_query", map[string]any{"name": "example.test", "server": server}, "allow_private")
	h.MustFail("dns_query", map[string]any{"name": "example.test", "server": server, "transport": "tcp"}, "allow_private")
	h.MustOK("dns_query", map[string]any{"name": "example.test", "server": server, "allow_private": true})

	hp := tooltest.New(t, "lowlevel", withAllowPorts(port+1))
	hp.MustFail("dns_query", map[string]any{"name": "example.test", "server": server}, "port allow list")

	hv := tooltest.New(t, "lowlevel")
	hv.MustFail("dns_query", map[string]any{"name": "example.test", "type": "BOGUS", "server": server}, "unknown DNS record type")
	hv.MustFail("dns_query", map[string]any{"name": "example.test", "transport": "quic", "server": server}, "unknown transport")
	hv.MustFail("dns_query", map[string]any{"name": "example.test", "server": server, "client_subnet": "nope"}, "invalid ecs")
}
