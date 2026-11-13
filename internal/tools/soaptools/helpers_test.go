package soaptools_test

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/HamedFathi/NetKitMCP/internal/tools/soaptools" // registers the tools
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

const (
	ns11     = "http://schemas.xmlsoap.org/soap/envelope/"
	ns12     = "http://www.w3.org/2003/05/soap-envelope"
	nsTypes  = "urn:example:bank:types"
	nsWSSE   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsWSU    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	pwText   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
	pwDigest = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	b64URI   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

// The bank WSDL is split over four documents to exercise import resolution:
//
//	wsdl/service.wsdl           bindings + service, wsdl:import abstract/port.wsdl
//	wsdl/abstract/port.wsdl     messages + portType, xs:import ../../xsd/types.xsd
//	xsd/types.xsd               elements, xs:include common.xsd
//	xsd/common.xsd              Money simple type
//
// {{BASE}} is replaced by the SOAP server URL.
var bankDocs = map[string]string{
	"wsdl/service.wsdl": `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions name="Bank" targetNamespace="urn:example:bank:wsdl"
    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
    xmlns:tns="urn:example:bank:wsdl">
  <wsdl:import namespace="urn:example:bank:wsdl" location="abstract/port.wsdl"/>
  <wsdl:binding name="BankSoap11" type="tns:Bank">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Transfer">
      <soap:operation soapAction="urn:example:bank#Transfer"/>
      <wsdl:input><soap:body use="literal"/></wsdl:input>
      <wsdl:output><soap:body use="literal"/></wsdl:output>
      <wsdl:fault name="TransferFault"><soap:fault name="TransferFault" use="literal"/></wsdl:fault>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="BankSoap12" type="tns:Bank">
    <soap12:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Transfer">
      <soap12:operation soapAction="urn:example:bank#Transfer"/>
      <wsdl:input><soap12:body use="literal"/></wsdl:input>
      <wsdl:output><soap12:body use="literal"/></wsdl:output>
      <wsdl:fault name="TransferFault"><soap12:fault name="TransferFault" use="literal"/></wsdl:fault>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="BankService">
    <wsdl:port name="BankSoap11Port" binding="tns:BankSoap11"><soap:address location="{{BASE}}/soap11"/></wsdl:port>
    <wsdl:port name="BankSoap12Port" binding="tns:BankSoap12"><soap12:address location="{{BASE}}/soap12"/></wsdl:port>
  </wsdl:service>
</wsdl:definitions>`,
	"wsdl/abstract/port.wsdl": `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions targetNamespace="urn:example:bank:wsdl"
    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:tns="urn:example:bank:wsdl"
    xmlns:t="urn:example:bank:types">
  <wsdl:types>
    <xs:schema targetNamespace="urn:example:bank:wsdl">
      <xs:import namespace="urn:example:bank:types" schemaLocation="../../xsd/types.xsd"/>
    </xs:schema>
  </wsdl:types>
  <wsdl:message name="TransferIn"><wsdl:part name="parameters" element="t:Transfer"/></wsdl:message>
  <wsdl:message name="TransferOut"><wsdl:part name="parameters" element="t:TransferResponse"/></wsdl:message>
  <wsdl:message name="TransferFault"><wsdl:part name="fault" element="t:TransferFault"/></wsdl:message>
  <wsdl:portType name="Bank">
    <wsdl:operation name="Transfer">
      <wsdl:documentation>Moves money between two accounts.</wsdl:documentation>
      <wsdl:input message="tns:TransferIn"/>
      <wsdl:output message="tns:TransferOut"/>
      <wsdl:fault name="TransferFault" message="tns:TransferFault"/>
    </wsdl:operation>
  </wsdl:portType>
</wsdl:definitions>`,
	"xsd/types.xsd": `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema targetNamespace="urn:example:bank:types" elementFormDefault="qualified"
    xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:t="urn:example:bank:types">
  <xs:include schemaLocation="common.xsd"/>
  <xs:element name="Transfer">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="from" type="xs:string"/>
        <xs:element name="to" type="xs:string"/>
        <xs:element name="amount" type="t:Money"/>
        <xs:element name="memo" type="xs:string" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute name="requestId" type="xs:string"/>
    </xs:complexType>
  </xs:element>
  <xs:element name="TransferResponse">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="id" type="xs:long"/>
        <xs:element name="accepted" type="xs:boolean"/>
        <xs:element name="balance" type="t:Money"/>
        <xs:element name="note" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
  <xs:element name="TransferFault">
    <xs:complexType><xs:sequence><xs:element name="code" type="xs:int"/></xs:sequence></xs:complexType>
  </xs:element>
</xs:schema>`,
	"xsd/common.xsd": `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema targetNamespace="urn:example:bank:types" xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="Money">
    <xs:restriction base="xs:decimal"><xs:fractionDigits value="2"/></xs:restriction>
  </xs:simpleType>
</xs:schema>`,
}

func bankDoc(name, base string) string {
	return strings.ReplaceAll(bankDocs[name], "{{BASE}}", base)
}

// captured is one request received by the fake SOAP server.
type captured struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

// reply is what the fake SOAP server answers.
type reply struct {
	Status      int
	ContentType string
	Body        string
}

// soapServer is an httptest server that serves the bank WSDL documents
// under /wsdl/ and /xsd/ and records every other request.
type soapServer struct {
	*httptest.Server
	mu      sync.Mutex
	reqs    []captured
	respond func(c captured) reply
}

func newSOAPServer(t *testing.T, respond func(c captured) reply) *soapServer {
	t.Helper()
	s := &soapServer{respond: respond}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if r.Method == http.MethodGet {
			if _, ok := bankDocs[name]; !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			io.WriteString(w, bankDoc(name, s.URL))
			return
		}
		b, _ := io.ReadAll(r.Body)
		c := captured{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(b)}
		s.mu.Lock()
		s.reqs = append(s.reqs, c)
		respond := s.respond
		s.mu.Unlock()
		rep := reply{Status: 200, ContentType: "text/xml; charset=utf-8", Body: emptyResponse11}
		if respond != nil {
			rep = respond(c)
		}
		if rep.ContentType != "" {
			w.Header().Set("Content-Type", rep.ContentType)
		}
		if rep.Status == 0 {
			rep.Status = 200
		}
		w.WriteHeader(rep.Status)
		io.WriteString(w, rep.Body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *soapServer) last(t *testing.T) captured {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		t.Fatal("the SOAP server received no request")
	}
	return s.reqs[len(s.reqs)-1]
}

func (s *soapServer) setRespond(f func(c captured) reply) {
	s.mu.Lock()
	s.respond = f
	s.mu.Unlock()
}

func (s *soapServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

const emptyResponse11 = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`

// writeBankFiles writes the bank documents into the harness read dir and
// returns the path of service.wsdl.
func writeBankFiles(t *testing.T, h *tooltest.Harness, base string) string {
	t.Helper()
	for name := range bankDocs {
		p := filepath.Join(h.ReadDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(bankDoc(name, base)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(h.ReadDir, "wsdl", "service.wsdl")
}

// xnode is an independent minimal XML tree used to inspect what the server
// received (deliberately not the soap package's own parser).
type xnode struct {
	Name xml.Name
	Attr []xml.Attr
	Kids []*xnode
	Text string
}

func parseX(t *testing.T, s string) *xnode {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader([]byte(s)))
	var stack []*xnode
	var root *xnode
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("server received malformed XML: %v\n%s", err, s)
		}
		switch tk := tok.(type) {
		case xml.StartElement:
			n := &xnode{Name: tk.Name, Attr: tk.Copy().Attr}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Kids = append(p.Kids, n)
			} else {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(tk)
			}
		}
	}
	if root == nil {
		t.Fatalf("no XML root in %q", s)
	}
	return root
}

func (n *xnode) is(space, local string) bool {
	return n != nil && n.Name.Space == space && n.Name.Local == local
}

func (n *xnode) child(space, local string) *xnode {
	if n == nil {
		return nil
	}
	for _, k := range n.Kids {
		if k.is(space, local) {
			return k
		}
	}
	return nil
}

func (n *xnode) attr(space, local string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, a := range n.Attr {
		if a.Name.Space == space && a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

func (n *xnode) text() string { return strings.TrimSpace(n.Text) }

// envelopeParts checks the envelope namespace and returns Header and the
// first Body child.
func envelopeParts(t *testing.T, body, envNS string) (header, first *xnode) {
	t.Helper()
	root := parseX(t, body)
	if !root.is(envNS, "Envelope") {
		t.Fatalf("root = {%s}%s, want {%s}Envelope\n%s", root.Name.Space, root.Name.Local, envNS, body)
	}
	b := root.child(envNS, "Body")
	if b == nil {
		t.Fatalf("no Body\n%s", body)
	}
	if len(b.Kids) > 0 {
		first = b.Kids[0]
	}
	return root.child(envNS, "Header"), first
}

// result mirrors the soap_request result.
type result struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	SOAPVersion string            `json:"soap_version"`
	Fault       map[string]any    `json:"fault"`
	Header      map[string]any    `json:"header"`
	Body        map[string]any    `json:"body"`
	RawXML      string            `json:"raw_xml"`
	Truncated   bool              `json:"truncated"`
	Request     struct {
		Endpoint    string            `json:"endpoint"`
		Operation   string            `json:"operation"`
		SOAPVersion string            `json:"soap_version"`
		SOAPAction  string            `json:"soap_action"`
		Headers     map[string]string `json:"headers"`
		Envelope    string            `json:"envelope"`
	} `json:"request"`
	Warnings []string `json:"warnings"`
}

func soapCall(t *testing.T, h *tooltest.Harness, args map[string]any) (result, *tooltest.Result) {
	t.Helper()
	r := h.MustOK("soap_request", args)
	var out result
	r.Decode(t, &out)
	return out, r
}

// path walks nested JSON objects.
func path(t *testing.T, v any, keys ...string) any {
	t.Helper()
	cur := v
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("at %q: %T is not an object (path %v)", k, cur, keys)
		}
		if cur, ok = m[k]; !ok {
			t.Fatalf("missing key %q (path %v) in %v", k, keys, m)
		}
	}
	return cur
}
