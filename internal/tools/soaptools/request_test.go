package soaptools_test

import (
	"crypto/sha1"
	"encoding/base64"
	"mime"
	"strings"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func transferResponse(envNS string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<e:Envelope xmlns:e="` + envNS + `"><e:Header><x:Trace xmlns:x="urn:trace">t-1</x:Trace></e:Header><e:Body>
<t:TransferResponse xmlns:t="urn:example:bank:types"><t:id>42</t:id><t:accepted>true</t:accepted><t:balance>12.50</t:balance><t:note>only one</t:note></t:TransferResponse>
</e:Body></e:Envelope>`
}

func bankServer(t *testing.T) *soapServer {
	return newSOAPServer(t, func(c captured) reply {
		if c.Path == "/soap12" {
			return reply{ContentType: "application/soap+xml; charset=utf-8", Body: transferResponse(ns12)}
		}
		return reply{ContentType: "text/xml; charset=utf-8", Body: transferResponse(ns11)}
	})
}

var transferArgs = map[string]any{"from": "NL01", "to": "NL02", "amount": 10.25, "memo": "rent & <stuff>", "@requestId": "r-7"}

// checkTransferBody verifies the body element built from transferArgs.
func checkTransferBody(t *testing.T, el *xnode, raw string) {
	t.Helper()
	if !el.is(nsTypes, "Transfer") {
		t.Fatalf("body element = {%s}%s\n%s", el.Name.Space, el.Name.Local, raw)
	}
	if v, _ := el.attr("", "requestId"); v != "r-7" {
		t.Fatalf("requestId attribute = %q\n%s", v, raw)
	}
	var got []string
	for _, k := range el.Kids {
		if k.Name.Space != nsTypes {
			t.Errorf("%s must be qualified in %s, got %q", k.Name.Local, nsTypes, k.Name.Space)
		}
		got = append(got, k.Name.Local+"="+k.text())
	}
	if want := "from=NL01,to=NL02,amount=10.25,memo=rent & <stuff>"; strings.Join(got, ",") != want {
		t.Fatalf("children = %s\nwant %s\n%s", strings.Join(got, ","), want, raw)
	}
}

func checkTypedTransferResult(t *testing.T, out result) {
	t.Helper()
	tr := path(t, out.Body, "TransferResponse").(map[string]any)
	if tr["id"] != 42.0 || tr["accepted"] != true || tr["balance"] != 12.5 {
		t.Fatalf("typed body = %v", tr)
	}
	notes, ok := tr["note"].([]any)
	if !ok || len(notes) != 1 || notes[0] != "only one" {
		t.Fatalf("note must be an array (maxOccurs=unbounded): %#v", tr["note"])
	}
	if path(t, out.Header, "Trace") != "t-1" {
		t.Fatalf("header = %v", out.Header)
	}
	if out.Fault != nil {
		t.Fatalf("unexpected fault %v", out.Fault)
	}
}

func TestRequestSOAP11ByOperation(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := bankServer(t)

	out, _ := soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs,
		"headers": map[string]string{"X-Trace-Id": "abc"},
	})
	c := srv.last(t)
	if c.Method != "POST" || c.Path != "/soap11" {
		t.Fatalf("%s %s", c.Method, c.Path)
	}
	if ct := c.Header.Get("Content-Type"); ct != "text/xml; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if sa := c.Header.Values("SOAPAction"); len(sa) != 1 || sa[0] != `"urn:example:bank#Transfer"` {
		t.Fatalf("SOAPAction = %q", sa)
	}
	if c.Header.Get("X-Trace-Id") != "abc" {
		t.Fatal("custom HTTP header not sent")
	}
	hdr, el := envelopeParts(t, c.Body, ns11)
	if hdr != nil {
		t.Fatalf("no soap:Header expected without header blocks\n%s", c.Body)
	}
	checkTransferBody(t, el, c.Body)

	if out.Status != 200 || out.SOAPVersion != "1.1" || out.Request.SOAPVersion != "1.1" ||
		out.Request.SOAPAction != "urn:example:bank#Transfer" || out.Request.Operation != "Transfer" ||
		out.Request.Endpoint != srv.URL+"/soap11" || out.Request.Envelope != c.Body {
		t.Fatalf("result = %+v", out)
	}
	if !strings.Contains(out.RawXML, "<t:balance>12.50</t:balance>") {
		t.Fatalf("raw_xml = %s", out.RawXML)
	}
	checkTypedTransferResult(t, out)
	if len(out.Warnings) != 0 {
		t.Fatalf("warnings: %v", out.Warnings)
	}

	// Wrapped args form, untyped response, soap_action override.
	out, _ = soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer",
		"args": map[string]any{"Transfer": transferArgs}, "typed_response": false, "soap_action": "urn:override",
	})
	c = srv.last(t)
	_, el = envelopeParts(t, c.Body, ns11)
	checkTransferBody(t, el, c.Body)
	if c.Header.Get("SOAPAction") != `"urn:override"` {
		t.Fatalf("SOAPAction = %q", c.Header.Get("SOAPAction"))
	}
	tr := path(t, out.Body, "TransferResponse").(map[string]any)
	if tr["id"] != "42" || tr["accepted"] != "true" || tr["note"] != "only one" {
		t.Fatalf("untyped body = %v", tr)
	}

	// Argument problems are warnings, not errors.
	out, _ = soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": map[string]any{"from": "x", "bogus": 1},
	})
	w := strings.Join(out.Warnings, "\n")
	if !strings.Contains(w, "missing required element to") || !strings.Contains(w, "bogus is not declared") {
		t.Fatalf("warnings = %v", out.Warnings)
	}

	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Withdraw"}, "available operations: Transfer")
	h.MustFail("soap_request", map[string]any{"operation": "Transfer", "endpoint": srv.URL}, "operation requires a WSDL")
	h.MustFail("soap_request", map[string]any{"endpoint": srv.URL}, "set operation")
	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "soap_version": "2.0"}, "unsupported soap_version")
}

func TestRequestSOAP12ByOperation(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := bankServer(t)

	for _, sel := range []map[string]any{{"soap_version": "1.2"}, {"port": "BankSoap12Port"}} {
		args := map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs}
		for k, v := range sel {
			args[k] = v
		}
		out, _ := soapCall(t, h, args)
		c := srv.last(t)
		if c.Path != "/soap12" {
			t.Fatalf("%v: the SOAP 1.2 port address must be used, got %s", sel, c.Path)
		}
		mt, params, err := mime.ParseMediaType(c.Header.Get("Content-Type"))
		if err != nil || mt != "application/soap+xml" || params["charset"] != "utf-8" || params["action"] != "urn:example:bank#Transfer" {
			t.Fatalf("%v: Content-Type = %q", sel, c.Header.Get("Content-Type"))
		}
		if _, ok := c.Header["Soapaction"]; ok {
			t.Fatalf("%v: SOAP 1.2 must not send a SOAPAction header", sel)
		}
		_, el := envelopeParts(t, c.Body, ns12)
		checkTransferBody(t, el, c.Body)
		if out.SOAPVersion != "1.2" || out.Request.SOAPVersion != "1.2" {
			t.Fatalf("%v: result = %+v", sel, out)
		}
		checkTypedTransferResult(t, out)
	}

	// Requesting 1.2 on the file-loaded WSDL works the same way.
	wsdl := writeBankFiles(t, h, srv.URL)
	out, _ := soapCall(t, h, map[string]any{"wsdl_file": wsdl, "operation": "Transfer", "args": transferArgs, "soap_version": "12"})
	if srv.last(t).Path != "/soap12" || out.SOAPVersion != "1.2" {
		t.Fatalf("file WSDL: path %s version %s", srv.last(t).Path, out.SOAPVersion)
	}
}

func TestRequestRPCInline(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := newSOAPServer(t, func(c captured) reply {
		return reply{Body: `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><n:AddResponse xmlns:n="http://example.com/calc"><result>5</result></n:AddResponse></s:Body></s:Envelope>`}
	})
	out, _ := soapCall(t, h, map[string]any{
		"wsdl": strings.ReplaceAll(calcWSDL, "{{BASE}}", srv.URL), "operation": "Add", "args": map[string]any{"a": 2, "b": 3},
	})
	c := srv.last(t)
	_, w := envelopeParts(t, c.Body, ns11)
	if c.Path != "/calc" || !w.is("http://example.com/calc", "Add") || c.Header.Get("SOAPAction") != `"urn:calc#Add"` {
		t.Fatalf("rpc request: %s %v\n%s", c.Path, c.Header, c.Body)
	}
	a, b := w.child("", "a"), w.child("", "b")
	if a == nil || b == nil || a.text() != "2" || b.text() != "3" {
		t.Fatalf("rpc parts must be unqualified accessors\n%s", c.Body)
	}
	if path(t, out.Body, "AddResponse", "result") != 5.0 {
		t.Fatalf("body = %v", out.Body)
	}
}

func TestRequestRawBody(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := newSOAPServer(t, func(c captured) reply {
		return reply{ContentType: "text/xml", Body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:PingResponse xmlns:m="urn:m"><m:v>1</m:v><m:v>2</m:v></m:PingResponse></soap:Body></soap:Envelope>`}
	})

	// Body content only: wrapped in a SOAP 1.1 envelope.
	out, _ := soapCall(t, h, map[string]any{
		"endpoint": srv.URL + "/raw", "raw_body": `<m:Ping xmlns:m="urn:m"><m:v>1</m:v></m:Ping>`, "soap_action": "urn:ping",
	})
	c := srv.last(t)
	if c.Path != "/raw" || c.Header.Get("SOAPAction") != `"urn:ping"` || c.Header.Get("Content-Type") != "text/xml; charset=utf-8" {
		t.Fatalf("%s %v", c.Path, c.Header)
	}
	_, el := envelopeParts(t, c.Body, ns11)
	if !el.is("urn:m", "Ping") || el.child("urn:m", "v").text() != "1" {
		t.Fatalf("raw body not wrapped\n%s", c.Body)
	}
	vs, ok := path(t, out.Body, "PingResponse", "v").([]any)
	if !ok || len(vs) != 2 || vs[0] != "1" {
		t.Fatalf("body = %v", out.Body)
	}

	// Body content with soap_version 1.2 and no action.
	soapCall(t, h, map[string]any{"endpoint": srv.URL, "raw_body": `<m:Ping xmlns:m="urn:m"/>`, "soap_version": "1.2"})
	c = srv.last(t)
	if ct := c.Header.Get("Content-Type"); ct != "application/soap+xml; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	envelopeParts(t, c.Body, ns12)

	// A full SOAP 1.2 envelope is sent as is (version detected), with
	// soap_headers injected into its Header.
	raw := `<?xml version="1.0"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body><m:Ping xmlns:m="urn:m"/></env:Body></env:Envelope>`
	out, _ = soapCall(t, h, map[string]any{
		"endpoint": srv.URL, "raw_body": raw, "soap_action": "urn:ping12",
		"soap_headers": []string{`<h:Tenant xmlns:h="urn:hdr">acme</h:Tenant>`},
	})
	c = srv.last(t)
	_, params, _ := mime.ParseMediaType(c.Header.Get("Content-Type"))
	if params["action"] != "urn:ping12" || c.Header.Get("SOAPAction") != "" {
		t.Fatalf("headers = %v", c.Header)
	}
	hdr, el := envelopeParts(t, c.Body, ns12)
	if hdr.child("urn:hdr", "Tenant").text() != "acme" || !el.is("urn:m", "Ping") {
		t.Fatalf("header not injected\n%s", c.Body)
	}
	if out.Request.SOAPVersion != "1.2" {
		t.Fatalf("version = %s", out.Request.SOAPVersion)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), "sent SOAP 1.2 but the response is SOAP 1.1") {
		t.Fatalf("version mismatch must be flagged: %v", out.Warnings)
	}

	// Without headers the full envelope is sent byte for byte.
	soapCall(t, h, map[string]any{"endpoint": srv.URL, "raw_body": raw})
	if srv.last(t).Body != raw {
		t.Fatalf("raw envelope altered:\n%s", srv.last(t).Body)
	}

	n := srv.count()
	h.MustFail("soap_request", map[string]any{"endpoint": srv.URL, "raw_body": `<m:Ping xmlns:m="urn:m">`}, "not well-formed")
	h.MustFail("soap_request", map[string]any{"endpoint": srv.URL, "raw_body": `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>`}, "not well-formed")
	h.MustFail("soap_request", map[string]any{"wsdl": strings.ReplaceAll(calcWSDL, "{{BASE}}", srv.URL), "operation": "Add",
		"args": map[string]any{"a": 1}, "raw_body": "<x/>"}, "not both")
	h.MustFail("soap_request", map[string]any{"raw_body": "<x/>"}, "no endpoint")
	if srv.count() != n {
		t.Fatal("invalid calls must not reach the server")
	}
}

func TestRequestFaults(t *testing.T) {
	h := tooltest.New(t, "soap")
	fault11 := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault>
<faultcode>soap:Server</faultcode><faultstring>Insufficient funds</faultstring>
<detail><t:TransferFault xmlns:t="urn:example:bank:types"><t:code>51</t:code></t:TransferFault></detail>
</soap:Fault></soap:Body></soap:Envelope>`
	fault12 := `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:b="urn:example:bank:types"><env:Body><env:Fault>
<env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>b:Limit</env:Value></env:Subcode></env:Code>
<env:Reason><env:Text xml:lang="en">Limit exceeded</env:Text></env:Reason>
<env:Detail><b:TransferFault><b:code>61</b:code></b:TransferFault></env:Detail>
</env:Fault></env:Body></env:Envelope>`
	srv := newSOAPServer(t, func(c captured) reply {
		if c.Path == "/soap12" {
			return reply{Status: 400, ContentType: "application/soap+xml", Body: fault12}
		}
		return reply{Status: 500, ContentType: "text/xml", Body: fault11}
	})

	out, r := soapCall(t, h, map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs})
	if r.IsError || out.Status != 500 || out.Fault == nil {
		t.Fatalf("1.1 fault must be a result: %+v", out)
	}
	if out.Fault["soap_version"] != "1.1" || out.Fault["faultcode"] != "soap:Server" || out.Fault["faultstring"] != "Insufficient funds" ||
		path(t, out.Fault, "detail", "TransferFault", "code") != "51" {
		t.Fatalf("1.1 fault = %v", out.Fault)
	}
	if len(out.Body) != 0 {
		t.Fatalf("body of a fault response = %v", out.Body)
	}

	out, r = soapCall(t, h, map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs, "soap_version": "1.2"})
	if r.IsError || out.Status != 400 || out.Fault == nil {
		t.Fatalf("1.2 fault must be a result: %+v", out)
	}
	subs, _ := out.Fault["subcodes"].([]any)
	if out.Fault["soap_version"] != "1.2" || out.Fault["code"] != "env:Sender" || len(subs) != 1 || subs[0] != "b:Limit" ||
		out.Fault["reason"] != "Limit exceeded" || path(t, out.Fault, "detail", "TransferFault", "code") != "61" {
		t.Fatalf("1.2 fault = %v", out.Fault)
	}
}

func TestRequestWSSecurityText(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := bankServer(t)
	const password = "Tr0ub4dor&3-secret"

	before := time.Now().UTC().Add(-time.Second)
	out, r := soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs,
		"soap_headers": []string{`<h:Tenant xmlns:h="urn:hdr">acme</h:Tenant>`, `<h2:Locale xmlns:h2="urn:hdr2">nl-NL</h2:Locale>`},
		"auth": map[string]any{"type": "ws_security", "username": "alice", "password": password,
			"ws_security": map[string]any{"timestamp": true, "ttl_seconds": 120, "must_understand": true}},
	})
	c := srv.last(t)
	if c.Header.Get("Authorization") != "" {
		t.Fatal("ws_security must not add HTTP auth")
	}
	hdr, el := envelopeParts(t, c.Body, ns11)
	checkTransferBody(t, el, c.Body)
	if hdr == nil || len(hdr.Kids) != 3 {
		t.Fatalf("want Security + 2 custom header blocks\n%s", c.Body)
	}
	sec := hdr.Kids[0]
	if !sec.is(nsWSSE, "Security") || !hdr.Kids[1].is("urn:hdr", "Tenant") || hdr.Kids[1].text() != "acme" ||
		!hdr.Kids[2].is("urn:hdr2", "Locale") || hdr.Kids[2].text() != "nl-NL" {
		t.Fatalf("header order/content wrong\n%s", c.Body)
	}
	if mu, _ := sec.attr(ns11, "mustUnderstand"); mu != "1" {
		t.Fatalf("SOAP 1.1 mustUnderstand = %q\n%s", mu, c.Body)
	}
	ut := sec.child(nsWSSE, "UsernameToken")
	pw := ut.child(nsWSSE, "Password")
	if ut.child(nsWSSE, "Username").text() != "alice" || pw.text() != password {
		t.Fatalf("UsernameToken wrong\n%s", c.Body)
	}
	if typ, _ := pw.attr("", "Type"); typ != pwText {
		t.Fatalf("Password Type = %q", typ)
	}
	ts := sec.child(nsWSU, "Timestamp")
	created, err1 := time.Parse(time.RFC3339, ts.child(nsWSU, "Created").text())
	expires, err2 := time.Parse(time.RFC3339, ts.child(nsWSU, "Expires").text())
	if err1 != nil || err2 != nil || expires.Sub(created) != 120*time.Second || created.Before(before) || created.After(time.Now().Add(time.Second)) {
		t.Fatalf("timestamp %v %v (%v %v)", created, expires, err1, err2)
	}

	// The password is never echoed back.
	// Check a distinctive fragment: the '&' is escaped in XML and in JSON,
	// so the full password would not match even if it leaked.
	if strings.Contains(r.Text, "Tr0ub4dor") || strings.Contains(string(r.Raw), "Tr0ub4dor") || strings.Contains(out.Request.Envelope, "Tr0ub4dor") {
		t.Fatalf("password leaked in the result:\n%s", r.Raw)
	}
	if !strings.Contains(out.Request.Envelope, "***") {
		t.Fatalf("redacted envelope = %s", out.Request.Envelope)
	}

	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer",
		"auth": map[string]any{"type": "ws_security", "password": "x"}}, "username is required")
	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer",
		"auth": map[string]any{"type": "ws_security", "username": "a", "ws_security": map[string]any{"password_type": "md5"}}}, "text or digest")
	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer",
		"soap_headers": []string{"<broken>"}}, "soap_headers[0] is not well-formed XML")
}

func TestRequestWSSecurityDigest(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := bankServer(t)
	const password = "digest-only-Pa55"

	var serverOK bool
	out, r := soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs, "soap_version": "1.2",
		"auth": map[string]any{"type": "ws_security", "username": "bob", "password": password,
			"ws_security": map[string]any{"password_type": "digest", "timestamp": true, "must_understand": true}},
	})
	c := srv.last(t)
	hdr, _ := envelopeParts(t, c.Body, ns12)
	sec := hdr.child(nsWSSE, "Security")
	if mu, _ := sec.attr(ns12, "mustUnderstand"); mu != "true" {
		t.Fatalf("SOAP 1.2 mustUnderstand = %q\n%s", mu, c.Body)
	}
	ut := sec.child(nsWSSE, "UsernameToken")
	pw, nonceEl, createdEl := ut.child(nsWSSE, "Password"), ut.child(nsWSSE, "Nonce"), ut.child(nsWSU, "Created")
	if typ, _ := pw.attr("", "Type"); typ != pwDigest {
		t.Fatalf("Password Type = %q", typ)
	}
	if enc, _ := nonceEl.attr("", "EncodingType"); enc != b64URI {
		t.Fatalf("Nonce EncodingType = %q", enc)
	}
	// Server-side verification: Base64(SHA1(nonce + created + password)).
	nonce, err := base64.StdEncoding.DecodeString(nonceEl.text())
	if err != nil || len(nonce) < 16 {
		t.Fatalf("nonce %q: %v", nonceEl.text(), err)
	}
	sum := sha1.Sum(append(append(nonce, createdEl.text()...), password...))
	if want := base64.StdEncoding.EncodeToString(sum[:]); pw.text() != want {
		t.Fatalf("digest %s, server computed %s", pw.text(), want)
	}
	serverOK = true
	if strings.Contains(c.Body, password) {
		t.Fatal("digest mode must not send the plain password")
	}
	if ts := sec.child(nsWSU, "Timestamp"); ts == nil || ts.child(nsWSU, "Created").text() != createdEl.text() {
		t.Fatalf("timestamp missing or inconsistent\n%s", c.Body)
	}
	exp, _ := time.Parse(time.RFC3339, sec.child(nsWSU, "Timestamp").child(nsWSU, "Expires").text())
	cr, _ := time.Parse(time.RFC3339, createdEl.text())
	if exp.Sub(cr) != 5*time.Minute {
		t.Fatalf("default TTL = %v", exp.Sub(cr))
	}
	if !serverOK || strings.Contains(string(r.Raw), password) || strings.Contains(r.Text, password) {
		t.Fatalf("password leaked:\n%s", r.Raw)
	}
	checkTypedTransferResult(t, out)

	// A fresh nonce per call.
	soapCall(t, h, map[string]any{
		"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs,
		"auth": map[string]any{"type": "ws_security", "username": "bob", "password": password, "ws_security": map[string]any{"password_type": "digest"}},
	})
	hdr2, _ := envelopeParts(t, srv.last(t).Body, ns11)
	if n2 := hdr2.child(nsWSSE, "Security").child(nsWSSE, "UsernameToken").child(nsWSSE, "Nonce").text(); n2 == nonceEl.text() {
		t.Fatal("nonce reused")
	}
}

func TestRequestNonSOAPResponse(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := newSOAPServer(t, func(c captured) reply {
		switch c.Path {
		case "/html":
			return reply{Status: 502, ContentType: "text/html", Body: "<html><body><h1>Bad Gateway</h1><p>upstream down<br></body></html>"}
		case "/json":
			return reply{Status: 200, ContentType: "application/json", Body: `{"error":"not soap"}`}
		case "/xml":
			return reply{Status: 200, ContentType: "application/xml", Body: `<status>ok</status>`}
		case "/empty":
			return reply{Status: 202}
		}
		return reply{}
	})
	for _, tc := range []struct{ path, warn, raw string }{
		{"/html", "could not parse the response as SOAP", "upstream down"},
		{"/json", "could not parse the response as SOAP", `"not soap"`},
		{"/xml", "not a SOAP envelope", "<status>ok</status>"},
	} {
		out, r := soapCall(t, h, map[string]any{"endpoint": srv.URL + tc.path, "raw_body": "<ping/>"})
		if r.IsError || out.Body != nil || out.Fault != nil {
			t.Fatalf("%s: %+v", tc.path, out)
		}
		if !strings.Contains(strings.Join(out.Warnings, "\n"), tc.warn) || !strings.Contains(out.RawXML, tc.raw) {
			t.Fatalf("%s: warnings %v raw %q", tc.path, out.Warnings, out.RawXML)
		}
	}
	out, _ := soapCall(t, h, map[string]any{"endpoint": srv.URL + "/html", "raw_body": "<ping/>"})
	if out.Status != 502 || !strings.HasPrefix(out.ContentType, "text/html") {
		t.Fatalf("status %d ct %q", out.Status, out.ContentType)
	}
	out, _ = soapCall(t, h, map[string]any{"endpoint": srv.URL + "/empty", "raw_body": "<ping/>"})
	if out.Status != 202 || len(out.Warnings) != 0 {
		t.Fatalf("empty 202: %+v", out)
	}

	// raw_xml is cut to max_response_bytes, but the envelope is still parsed.
	big := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><r>` + strings.Repeat("x", 5000) + `</r></s:Body></s:Envelope>`
	srv.setRespond(func(captured) reply { return reply{Body: big} })
	out, _ = soapCall(t, h, map[string]any{"endpoint": srv.URL, "raw_body": "<ping/>", "max_response_bytes": 1000})
	if !out.Truncated || len(out.RawXML) != 1000 || len(path(t, out.Body, "r").(string)) != 5000 {
		t.Fatalf("truncated=%v raw=%d body=%v", out.Truncated, len(out.RawXML), out.Body)
	}
}

func TestRequestSSRFGuard(t *testing.T) {
	h := tooltest.New(t, "soap", tooltest.WithPrivateMode(config.PrivateOptIn))
	srv := bankServer(t)

	h.MustFail("soap_request", map[string]any{"endpoint": srv.URL, "raw_body": "<ping/>"}, "allow_private")
	h.MustFail("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl"}, "allow_private")
	h.MustFail("soap_request", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer"}, "allow_private")
	if srv.count() != 0 {
		t.Fatal("blocked calls reached the server")
	}

	// A file WSDL whose endpoint is loopback is blocked at request time.
	wsdl := writeBankFiles(t, h, srv.URL)
	h.MustFail("soap_request", map[string]any{"wsdl_file": wsdl, "operation": "Transfer", "args": transferArgs}, "allow_private")

	out, _ := soapCall(t, h, map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "args": transferArgs, "allow_private": true})
	checkTypedTransferResult(t, out)
	h.MustOK("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "allow_private": true})
}
