package soaptools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

type description struct {
	Name            string   `json:"name"`
	TargetNamespace string   `json:"target_namespace"`
	Documents       []string `json:"documents"`
	Services        []struct {
		Name  string `json:"name"`
		Ports []struct {
			Name        string `json:"name"`
			Binding     string `json:"binding"`
			SOAPVersion string `json:"soap_version"`
			Style       string `json:"style"`
			Address     string `json:"address"`
			Operations  []struct {
				Name       string `json:"name"`
				SOAPAction string `json:"soap_action"`
				Style      string `json:"style"`
				InputUse   string `json:"input_use"`
			} `json:"operations"`
		} `json:"ports"`
	} `json:"services"`
	Operations map[string]struct {
		Documentation string          `json:"documentation"`
		Input         json.RawMessage `json:"input"`
		Output        json.RawMessage `json:"output"`
		Faults        []string        `json:"faults"`
	} `json:"operations"`
	Operation *struct {
		Name        string   `json:"name"`
		Port        string   `json:"port"`
		Endpoint    string   `json:"endpoint"`
		SOAPVersion string   `json:"soap_version"`
		SOAPAction  string   `json:"soap_action"`
		Wrapped     bool     `json:"wrapped"`
		OtherPorts  []string `json:"other_ports"`
		Faults      []struct {
			Name   string         `json:"name"`
			Detail map[string]any `json:"detail"`
		} `json:"faults"`
	} `json:"operation"`
	Warnings []string `json:"warnings"`
}

const bankInput = `{"Transfer":{"@requestId?":"string","from":"string","to":"string","amount":"number","memo?":"string"}}`
const bankOutput = `{"TransferResponse":{"id":"integer","accepted":"boolean","balance":"number","note?":["string"]}}`

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func sameJSON(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("shape mismatch\n got: %s\nwant: %s", compactJSON(t, got), want)
	}
}

// checkBank verifies the overview of the (imported) bank WSDL.
func checkBank(t *testing.T, d description, base string) {
	t.Helper()
	if len(d.Warnings) != 0 {
		t.Fatalf("warnings: %v", d.Warnings)
	}
	if len(d.Documents) != 4 {
		t.Fatalf("documents = %v (want service, port, types, common)", d.Documents)
	}
	if d.Name != "Bank" || d.TargetNamespace != "urn:example:bank:wsdl" {
		t.Fatalf("name/tns = %q %q", d.Name, d.TargetNamespace)
	}
	if len(d.Services) != 1 || d.Services[0].Name != "BankService" || len(d.Services[0].Ports) != 2 {
		t.Fatalf("services = %+v", d.Services)
	}
	p11, p12 := d.Services[0].Ports[0], d.Services[0].Ports[1]
	if p11.Name != "BankSoap11Port" || p11.SOAPVersion != "1.1" || p11.Address != base+"/soap11" || p11.Style != "document" {
		t.Fatalf("1.1 port = %+v", p11)
	}
	if p12.Name != "BankSoap12Port" || p12.SOAPVersion != "1.2" || p12.Address != base+"/soap12" {
		t.Fatalf("1.2 port = %+v", p12)
	}
	if op := p11.Operations; len(op) != 1 || op[0].Name != "Transfer" || op[0].SOAPAction != "urn:example:bank#Transfer" || op[0].InputUse != "literal" {
		t.Fatalf("operations = %+v", op)
	}
	tr, ok := d.Operations["Transfer"]
	if !ok {
		t.Fatalf("operations = %v", d.Operations)
	}
	if tr.Documentation != "Moves money between two accounts." || !reflect.DeepEqual(tr.Faults, []string{"TransferFault"}) {
		t.Fatalf("transfer = %+v", tr)
	}
	sameJSON(t, tr.Input, bankInput)
	sameJSON(t, tr.Output, bankOutput)
}

func TestDescribeURLWithImports(t *testing.T) {
	h := tooltest.New(t, "soap")
	srv := newSOAPServer(t, nil)

	r := h.MustOK("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl"})
	var d description
	r.Decode(t, &d)
	checkBank(t, d, srv.URL)
	want := []string{
		srv.URL + "/wsdl/service.wsdl",
		srv.URL + "/wsdl/abstract/port.wsdl", // wsdl:import relative to the WSDL URL
		srv.URL + "/xsd/types.xsd",           // xs:import ../../ relative to port.wsdl
		srv.URL + "/xsd/common.xsd",          // xs:include relative to types.xsd
	}
	if !reflect.DeepEqual(d.Documents, want) {
		t.Fatalf("documents\n got %v\nwant %v", d.Documents, want)
	}

	// One operation in detail.
	r = h.MustOK("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "transfer"})
	d = description{}
	r.Decode(t, &d)
	o := d.Operation
	if o == nil || o.Name != "Transfer" || o.Port != "BankSoap11Port" || o.SOAPVersion != "1.1" || !o.Wrapped ||
		o.Endpoint != srv.URL+"/soap11" || o.SOAPAction != "urn:example:bank#Transfer" {
		t.Fatalf("operation = %+v", o)
	}
	if !reflect.DeepEqual(o.OtherPorts, []string{"BankService/BankSoap12Port (SOAP 1.2)"}) {
		t.Fatalf("other_ports = %v (must not list the selected port)", o.OtherPorts)
	}
	if len(o.Faults) != 1 || path(t, o.Faults[0].Detail, "TransferFault", "code") != "integer" {
		t.Fatalf("faults = %+v", o.Faults)
	}
	// Selecting the SOAP 1.2 port.
	r = h.MustOK("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Transfer", "port": "BankSoap12Port"})
	d = description{}
	r.Decode(t, &d)
	if d.Operation.SOAPVersion != "1.2" || d.Operation.Endpoint != srv.URL+"/soap12" {
		t.Fatalf("1.2 operation = %+v", d.Operation)
	}

	h.MustFail("soap_describe", map[string]any{"wsdl_url": srv.URL + "/wsdl/service.wsdl", "operation": "Nope"}, "available operations: Transfer")
	h.MustFail("soap_describe", map[string]any{"wsdl_url": srv.URL + "/missing.wsdl"}, "404")
}

func TestDescribeFile(t *testing.T) {
	h := tooltest.New(t, "soap")
	wsdl := writeBankFiles(t, h, "http://bank.example")

	r := h.MustOK("soap_describe", map[string]any{"wsdl_file": wsdl})
	var d description
	r.Decode(t, &d)
	checkBank(t, d, "http://bank.example")
	if !strings.HasSuffix(filepath.ToSlash(d.Documents[2]), "/xsd/types.xsd") {
		t.Fatalf("documents = %v", d.Documents)
	}

	// Relative path (resolved against the first read dir).
	h.MustOK("soap_describe", map[string]any{"wsdl_file": "wsdl/service.wsdl"})

	// A file outside the read dirs is refused, also when reached via an import.
	outside := filepath.Join(filepath.Dir(h.ReadDir), "secret.xsd")
	if err := os.WriteFile(outside, []byte(`<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	h.MustFail("soap_describe", map[string]any{"wsdl_file": outside}, "outside the allowed read directories")
	evil := h.WriteInput("evil.wsdl", []byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:e">
  <types><xs:schema targetNamespace="urn:e"><xs:import namespace="urn:x" schemaLocation="../secret.xsd"/></xs:schema></types>
</definitions>`))
	r = h.MustOK("soap_describe", map[string]any{"wsdl_file": evil})
	d = description{}
	r.Decode(t, &d)
	if len(d.Documents) != 1 || !strings.Contains(strings.Join(d.Warnings, "\n"), "outside the allowed read directories") {
		t.Fatalf("escaping import must be refused: docs=%v warnings=%v", d.Documents, d.Warnings)
	}

	h.MustFail("soap_describe", map[string]any{"wsdl_file": wsdl, "wsdl": "<x/>"}, "only one of")
	h.MustFail("soap_describe", map[string]any{}, "set one of")
}

const calcWSDL = `<definitions name="Calc" targetNamespace="http://example.com/calc/wsdl"
    xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="http://example.com/calc/wsdl">
  <message name="AddRequest"><part name="a" type="xsd:int"/><part name="b" type="xsd:int"/></message>
  <message name="AddResponse"><part name="result" type="xsd:int"/></message>
  <portType name="CalcPT"><operation name="Add"><input message="tns:AddRequest"/><output message="tns:AddResponse"/></operation></portType>
  <binding name="CalcBinding" type="tns:CalcPT">
    <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Add">
      <soap:operation soapAction="urn:calc#Add"/>
      <input><soap:body use="literal" namespace="http://example.com/calc"/></input>
      <output><soap:body use="literal" namespace="http://example.com/calc"/></output>
    </operation>
  </binding>
  <service name="CalcService"><port name="CalcPort" binding="tns:CalcBinding"><soap:address location="{{BASE}}/calc"/></port></service>
</definitions>`

func TestDescribeInline(t *testing.T) {
	h := tooltest.New(t, "soap")
	r := h.MustOK("soap_describe", map[string]any{"wsdl": strings.ReplaceAll(calcWSDL, "{{BASE}}", "http://calc.example")})
	var d description
	r.Decode(t, &d)
	if len(d.Services) != 1 || d.Services[0].Ports[0].Style != "rpc" || d.Services[0].Ports[0].Operations[0].SOAPAction != "urn:calc#Add" {
		t.Fatalf("services = %+v", d.Services)
	}
	if !reflect.DeepEqual(d.Documents, []string{"(inline)"}) {
		t.Fatalf("documents = %v", d.Documents)
	}
	sameJSON(t, d.Operations["Add"].Input, `{"Add":{"a":"integer","b":"integer"}}`)
	sameJSON(t, d.Operations["Add"].Output, `{"AddResponse":{"result":"integer"}}`)

	// Relative imports cannot be resolved for inline WSDL; file: is never allowed.
	r = h.MustOK("soap_describe", map[string]any{"wsdl": `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:e">
  <types><xs:schema targetNamespace="urn:e">
    <xs:import namespace="urn:a" schemaLocation="types.xsd"/>
    <xs:import namespace="urn:b" schemaLocation="file:///etc/passwd"/>
  </xs:schema></types>
</definitions>`})
	d = description{}
	r.Decode(t, &d)
	w := strings.Join(d.Warnings, "\n")
	if !strings.Contains(w, "inline WSDL") || !strings.Contains(w, `unsupported scheme "file"`) {
		t.Fatalf("warnings = %v", d.Warnings)
	}

	h.MustFail("soap_describe", map[string]any{"wsdl": `<description xmlns="http://www.w3.org/ns/wsdl"/>`}, "WSDL 2.0")
	h.MustFail("soap_describe", map[string]any{"wsdl": `<html><body>`}, "parsing WSDL")
}
