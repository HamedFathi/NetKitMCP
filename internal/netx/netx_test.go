package netx

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUnescape(t *testing.T) {
	cases := map[string]string{
		`plain`:            "plain",
		`a\r\nb`:           "a\r\nb",
		`\x41\x42\t\0`:     "AB\t\x00",
		`\\n`:              `\n`,
		"\\u00e9":          "\u00e9",
		`keep \q unknown`:  `keep \q unknown`,
		`trailing\`:        `trailing\`,
		`quote \"x\" \'y'`: `quote "x" 'y'`,
	}
	for in, want := range cases {
		got, err := Unescape(in)
		if err != nil || string(got) != want {
			t.Errorf("Unescape(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`\x4`, `\xZZ`, `\u12`} {
		if _, err := Unescape(bad); err == nil {
			t.Errorf("Unescape(%q): expected error", bad)
		}
	}
}

func TestParseHex(t *testing.T) {
	for _, in := range []string{"deadbeef", "DE AD BE EF", "de:ad:be:ef", "0xdeadbeef", "de-ad\nbe-ef"} {
		b, err := ParseHex(in)
		if err != nil || !bytes.Equal(b, []byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("ParseHex(%q) = %x, %v", in, b, err)
		}
	}
	if _, err := ParseHex("abc"); err == nil {
		t.Error("odd-length hex accepted")
	}
}

func TestJoinHostPort(t *testing.T) {
	cases := map[string]string{"1.1.1.1": "1.1.1.1:53", "dns.test:5353": "dns.test:5353", "::1": "[::1]:53", "[::1]:54": "[::1]:54"}
	for in, want := range cases {
		if got := JoinHostPort(in, 53); got != want {
			t.Errorf("JoinHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	q, err := BuildQuery(&DNSRequest{Name: "2001:db8::1", Type: dns.TypePTR, RD: true, DO: true, ECS: "2001:db8::/48"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(q.Question[0].Name, ".ip6.arpa.") || !q.RecursionDesired {
		t.Fatalf("question: %v", q.Question)
	}
	opt := q.IsEdns0()
	if opt == nil || !opt.Do() || opt.UDPSize() != 1232 || len(opt.Option) != 1 {
		t.Fatalf("opt: %v", opt)
	}
	if sub := opt.Option[0].(*dns.EDNS0_SUBNET); sub.Family != 2 || sub.SourceNetmask != 48 {
		t.Fatalf("ecs: %v", sub)
	}
	q, err = BuildQuery(&DNSRequest{Name: "example.com", Type: dns.TypeA, Transport: DNSDoH, NoEDNS: true})
	if err != nil || q.Id != 0 || q.IsEdns0() != nil || q.Question[0].Name != "example.com." {
		t.Fatalf("doh query: %v %v", q, err)
	}
	if _, err := BuildQuery(&DNSRequest{Name: "x.test", Type: dns.TypeA, NoEDNS: true, DO: true}); err == nil {
		t.Fatal("DO without EDNS accepted")
	}
	if _, err := ParseType("TYPE65"); err != nil {
		t.Fatal(err)
	}
	if ty, _ := ParseType("svcb"); ty != dns.TypeSVCB {
		t.Fatal("svcb type")
	}
}

func TestRecords(t *testing.T) {
	rr, _ := dns.NewRR(`example.test. 60 IN SOA ns.example.test. admin.example.test. 1 2 3 4 5`)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	recs := Records([]dns.RR{rr, opt})
	if len(recs) != 1 || recs[0].Type != "SOA" || recs[0].Fields["serial"] != uint32(1) || recs[0].TTL != 60 ||
		recs[0].Data != "ns.example.test. admin.example.test. 1 2 3 4 5" {
		t.Fatalf("records: %+v", recs)
	}
}

func TestTCPExchangeNoRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	var d net.Dialer
	res, err := TCPExchange(context.Background(), TCPRequest{Addr: ln.Addr().String(), Dial: d.DialContext,
		Send: strings.NewReader("fire"), NoRead: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.EndedBy != EndedNoRead || res.BytesSent != 4 {
		t.Fatalf("result: %+v", res)
	}
	select {
	case b := <-got:
		if string(b) != "fire" {
			t.Fatalf("server got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server got nothing")
	}
}
