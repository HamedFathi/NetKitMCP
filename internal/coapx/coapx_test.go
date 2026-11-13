package coapx

import (
	"testing"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
)

func TestParseURL(t *testing.T) {
	cases := []struct {
		in, network, host, path string
		tls                     bool
		queries                 int
	}{
		{"coap://h/a/b?x=1&y=%20z", "udp", "h:5683", "/a/b", false, 2},
		{"h:1234", "udp", "h:1234", "/", false, 0},
		{"coap+tcp://h", "tcp", "h:5683", "/", false, 0},
		{"coaps+tcp://h/x", "tcp", "h:5684", "/x", true, 0},
		{"coap://[::1]:99/", "udp", "[::1]:99", "/", false, 0},
	}
	for _, c := range cases {
		got, err := ParseURL(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got.Network != c.network || got.Host != c.host || got.Path != c.path || got.TLS != c.tls || len(got.Queries) != c.queries {
			t.Errorf("%s: got %+v", c.in, got)
		}
	}
	if got, _ := ParseURL("coap://h/?x=1&y=%20z"); got.Queries[1] != "y= z" {
		t.Errorf("query not unescaped: %v", got.Queries)
	}
	for _, bad := range []string{"coaps://h", "http://h", "coap:///x"} {
		if _, err := ParseURL(bad); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}

func TestParseMediaType(t *testing.T) {
	for in, want := range map[string]message.MediaType{
		"0": message.TextPlain, "50": message.AppJSON, "json": message.AppJSON, "application/json": message.AppJSON,
		"text/plain": message.TextPlain, "application/cbor": message.AppCBOR, "octet-stream": message.AppOctets, "xml": message.AppXML,
	} {
		got, err := ParseMediaType(in)
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v", in, got, err)
		}
	}
	if _, err := ParseMediaType("nope/nope"); err == nil {
		t.Error("expected an error")
	}
}

func TestOptions(t *testing.T) {
	for in, want := range map[string]message.OptionID{"uri-query": message.URIQuery, "ETag": message.ETag, "max_age": message.MaxAge, "17": message.Accept} {
		got, err := ParseOptionID(in)
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v", in, got, err)
		}
	}
	if _, err := ParseOptionID("bogus"); err == nil {
		t.Error("expected an error")
	}
	o, err := encodeOption(Option{Name: "max-age", Value: "300"})
	if err != nil || o.ID != message.MaxAge || len(o.Value) != 2 {
		t.Fatalf("max-age: %+v %v", o, err)
	}
	o, err = encodeOption(Option{Name: "etag", Value: "0xBEEF"})
	if err != nil || string(o.Value) != "\xbe\xef" {
		t.Fatalf("etag: %+v %v", o, err)
	}
	o, err = encodeOption(Option{Name: "accept", Value: "json"})
	if err != nil || len(o.Value) != 1 || o.Value[0] != byte(message.AppJSON) {
		t.Fatalf("accept: %+v %v", o, err)
	}
	if _, err := encodeOption(Option{Name: "max-age", Value: "x"}); err == nil {
		t.Error("expected an error for a non-numeric uint option")
	}
	if _, err := encodeOption(Option{Name: "etag", Value: "zz"}); err == nil {
		t.Error("expected an error for a non-hex opaque option")
	}

	desc := DescribeOptions(message.Options{
		{ID: message.ContentFormat, Value: []byte{50}},
		{ID: message.MaxAge, Value: []byte{60}},
		{ID: message.ETag, Value: []byte{1, 2}},
		{ID: message.LocationPath, Value: []byte("res")},
	})
	if desc[0].Value != "50 (application/json)" || desc[1].Value != uint32(60) || desc[2].Value != "0102" || desc[3].Value != "res" {
		t.Fatalf("describe: %+v", desc)
	}
}

func TestCodeString(t *testing.T) {
	for c, want := range map[codes.Code]string{codes.Content: "2.05", codes.NotFound: "4.04", codes.InternalServerError: "5.00", codes.GET: "0.01"} {
		if got := CodeString(c); got != want {
			t.Errorf("%v: got %s, want %s", c, got, want)
		}
	}
	if _, err := methodCode("brew"); err == nil {
		t.Error("expected an error for an unknown method")
	}
	if c, _ := methodCode("ipatch"); c != codes.IPATCH {
		t.Errorf("ipatch: %v", c)
	}
}
