package soap

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fileFetcher reads imports from disk (tests only; the tool uses fileio).
var fileFetcher = FetchFunc(func(_ context.Context, loc Location) ([]byte, error) {
	if loc.File == "" {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(loc.File)
})

func loadFixture(t *testing.T, name string) *Definitions {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defs, err := Load(context.Background(), data, Location{File: path}, fileFetcher, LoadOptions{})
	if err != nil {
		t.Fatalf("Load %s: %v", name, err)
	}
	for i, d := range defs.Documents {
		defs.Documents[i] = filepath.ToSlash(d)
	}
	return defs
}

func golden(t *testing.T, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/soap -update)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, buf.String(), want)
	}
}

func TestDescribeGolden(t *testing.T) {
	cases := []struct{ wsdl, op, golden string }{
		{"weather.wsdl", "", "weather.describe.json"},
		{"weather.wsdl", "GetForecast", "weather.operation.json"},
		{"calculator-rpc.wsdl", "", "calculator.describe.json"},
		{"xsimport.wsdl", "", "xsimport.describe.json"},
		{"wsdlimport.wsdl", "Echo", "wsdlimport.operation.json"},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			defs := loadFixture(t, c.wsdl)
			desc, err := defs.Describe(c.op, "", "")
			if err != nil {
				t.Fatal(err)
			}
			golden(t, c.golden, desc)
		})
	}
}

func TestImportsResolved(t *testing.T) {
	defs := loadFixture(t, "xsimport.wsdl")
	if len(defs.Documents) != 3 {
		t.Fatalf("documents = %v", defs.Documents)
	}
	if w := defs.AllWarnings(); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	o, err := defs.FindOperation("PlaceOrder", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Chameleon include: OrderLine adopts the orders namespace.
	in := defs.Body(o, false)
	line := in.Fields[0].FindChild("line")
	if line == nil || line.FindChild("qty") == nil || !line.IsArray() {
		t.Fatalf("line not resolved: %+v", line)
	}
	if line.NS != "" {
		t.Fatalf("unqualified local element got namespace %q", line.NS)
	}

	defs = loadFixture(t, "wsdlimport.wsdl")
	o, err = defs.FindOperation("Echo", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if o.Binding.SOAPVersion != "1.2" || o.Address != "http://localhost/echo" || o.Op.Input.IsZero() {
		t.Fatalf("unexpected op binding: %+v", o)
	}
}

func TestWSDL20Rejected(t *testing.T) {
	_, err := Load(context.Background(), []byte(`<description xmlns="http://www.w3.org/ns/wsdl"/>`), Location{}, nil, LoadOptions{})
	if err == nil || !strings.Contains(err.Error(), "WSDL 2.0") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveLocation(t *testing.T) {
	l, err := ResolveLocation(Location{URL: "http://h/a/svc.wsdl"}, "../x/t.xsd")
	if err != nil || l.URL != "http://h/x/t.xsd" {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := ResolveLocation(Location{URL: "http://h/a/svc.wsdl"}, "file:///etc/passwd"); err == nil {
		t.Fatal("file: scheme must be rejected")
	}
	l, err = ResolveLocation(Location{URL: "http://h/a/svc.wsdl"}, "/etc/passwd")
	if err != nil || l.File != "" || l.URL != "http://h/etc/passwd" {
		t.Fatalf("absolute path from URL base must stay a URL: %v %v", l, err)
	}
	if _, err := ResolveLocation(Location{}, "types.xsd"); err == nil {
		t.Fatal("relative import from inline WSDL must fail")
	}
	l, err = ResolveLocation(Location{File: filepath.Join("dir", "a.wsdl")}, "schemas/b.xsd")
	if err != nil || l.File != filepath.Join("dir", "schemas", "b.xsd") {
		t.Fatalf("%v %v", l, err)
	}
}

func buildEnvelope(t *testing.T, defs *Definitions, op string, args any, version string) (*Prepared, *Node) {
	t.Helper()
	p, err := Prepare(PrepareOptions{Defs: defs, Operation: op, Args: args, Version: version})
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseXML([]byte(p.Envelope))
	if err != nil {
		t.Fatalf("envelope not well-formed: %v\n%s", err, p.Envelope)
	}
	return p, root
}

func bodyChild(t *testing.T, root *Node) *Node {
	t.Helper()
	body := root.Child(root.Name.Space, "Body")
	if body == nil || len(body.Children) == 0 {
		t.Fatalf("no body content")
	}
	return body.Children[0]
}

func TestBuildDocumentWrapped(t *testing.T) {
	defs := loadFixture(t, "weather.wsdl")
	args := map[string]any{"city": "Amsterdam", "days?": float64(3), "include": []any{"wind", "uv"}}
	p, root := buildEnvelope(t, defs, "GetForecast", args, "")
	if p.Version != "1.1" || p.Action != "http://example.com/weather/GetForecast" || p.ContentType != "text/xml; charset=utf-8" {
		t.Fatalf("prepared = %+v", p)
	}
	if !root.Is(NSSOAP11Env, "Envelope") {
		t.Fatalf("root = %v", root.Name)
	}
	gf := bodyChild(t, root)
	if !gf.Is("http://example.com/weather", "GetForecast") {
		t.Fatalf("body child = %v", gf.Name)
	}
	var names []string
	for _, c := range gf.Children {
		if c.Name.Space != "http://example.com/weather" {
			t.Errorf("%s should be qualified, got ns %q", c.Name.Local, c.Name.Space)
		}
		names = append(names, c.Name.Local+"="+c.Text)
	}
	if got := strings.Join(names, ","); got != "city=Amsterdam,days=3,include=wind,include=uv" {
		t.Fatalf("children = %s\n%s", got, p.Envelope)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings: %v", p.Warnings)
	}

	// Wrapped form ({"GetForecast": {...}}) and SOAP 1.2 content type.
	p, root = buildEnvelope(t, defs, "GetForecast", map[string]any{"GetForecast": map[string]any{"zip": "1011"}}, "1.2")
	if !root.Is(NSSOAP12Env, "Envelope") || p.ContentType != `application/soap+xml; charset=utf-8; action="http://example.com/weather/GetForecast"` {
		t.Fatalf("1.2: %+v", p)
	}
	if gf := bodyChild(t, root); gf.Children[0].Name.Local != "zip" {
		t.Fatalf("unexpected body\n%s", p.Envelope)
	}
	// SOAP 1.2 port is chosen when version 1.2 is requested.
	if p.Op.Port != "WeatherSoap12" {
		t.Fatalf("port = %s", p.Op.Port)
	}
}

func TestBuildMissingChoiceWarns(t *testing.T) {
	defs := loadFixture(t, "weather.wsdl")
	p, _ := buildEnvelope(t, defs, "GetForecast", map[string]any{"days": float64(1.5), "bogus": "x"}, "")
	w := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"none of the choice elements", "not an integer", "bogus is not declared"} {
		if !strings.Contains(w, want) {
			t.Errorf("missing warning %q in:\n%s", want, w)
		}
	}
}

func TestBuildUnqualifiedWithAttributes(t *testing.T) {
	defs := loadFixture(t, "xsimport.wsdl")
	args := map[string]any{
		"@requestId": "r-1",
		"customer":   "ACME",
		"line": []any{
			map[string]any{"sku": "A1", "qty": float64(2), "tags": []any{"x", "y"}},
		},
	}
	p, root := buildEnvelope(t, defs, "PlaceOrder", args, "")
	po := bodyChild(t, root)
	if !po.Is("http://example.com/orders", "PlaceOrder") || po.Attr("requestId") != "r-1" {
		t.Fatalf("root element wrong\n%s", p.Envelope)
	}
	cust := po.Child("", "customer")
	line := po.Child("", "line")
	if cust == nil || line == nil {
		t.Fatalf("local elements must be unqualified\n%s", p.Envelope)
	}
	if tags := line.Child("", "tags"); tags == nil || tags.Text != "x y" {
		t.Fatalf("list type not serialized\n%s", p.Envelope)
	}
}

func TestBuildRPC(t *testing.T) {
	defs := loadFixture(t, "calculator-rpc.wsdl")
	p, root := buildEnvelope(t, defs, "Add", map[string]any{"a": float64(2), "b": float64(3)}, "")
	w := bodyChild(t, root)
	if !w.Is("http://example.com/calc", "Add") {
		t.Fatalf("wrapper = %v\n%s", w.Name, p.Envelope)
	}
	a, b := w.Child("", "a"), w.Child("", "b")
	if a == nil || b == nil || a.Text != "2" || b.Text != "3" {
		t.Fatalf("part accessors wrong\n%s", p.Envelope)
	}
	if p.Action != "urn:calc#Add" {
		t.Fatalf("action %q", p.Action)
	}
	p, root = buildEnvelope(t, defs, "Sum", map[string]any{"numbers": map[string]any{"item": []any{1.0, 2.0, 3.0}}}, "")
	n := bodyChild(t, root).Child("", "numbers")
	if n == nil || len(n.ChildrenNamed("", "item")) != 3 {
		t.Fatalf("rpc complex part wrong\n%s", p.Envelope)
	}
}

func TestRawEnvelopeInjection(t *testing.T) {
	hdr := []string{`<h:A xmlns:h="urn:h">1</h:A>`}
	cases := map[string]string{
		"no header":    `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><x/></s:Body></s:Envelope>`,
		"empty header": `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header/><s:Body><x/></s:Body></s:Envelope>`,
		"header":       `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><o:B xmlns:o="urn:o"/></s:Header><s:Body><x/></s:Body></s:Envelope>`,
		"default ns":   `<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body><x xmlns=""/></Body></Envelope>`,
	}
	for name, raw := range cases {
		out, ver, isEnv, err := RawEnvelope(raw, hdr)
		if err != nil || !isEnv {
			t.Fatalf("%s: %v %v", name, isEnv, err)
		}
		root, err := ParseXML([]byte(out))
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		h := root.Child(root.Name.Space, "Header")
		if h == nil || h.Child("urn:h", "A") == nil {
			t.Fatalf("%s: header not injected\n%s", name, out)
		}
		if name == "default ns" && ver != "1.2" {
			t.Fatalf("version %s", ver)
		}
	}
	if _, _, isEnv, _ := RawEnvelope(`<m:Ping xmlns:m="urn:m"/>`, nil); isEnv {
		t.Fatal("fragment detected as envelope")
	}
}

func TestPasswordDigestVector(t *testing.T) {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	// Independently computed: base64(sha1(nonce + created + password)).
	if got := PasswordDigest(nonce, "2026-01-02T03:04:05.000Z", "s3cret"); got != "ihTghcJMN0f+NNk67HD7TiIqB40=" {
		t.Fatalf("digest = %s", got)
	}
	w := WSSecurity{Username: "bob", Password: "s3cret", Digest: true, Timestamp: true, MustUnderstand: true,
		Now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Nonce: nonce, TTL: time.Minute}
	h, err := w.Header("1.2")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<wsse:Password Type="` + PasswordDigURI + `">ihTghcJMN0f+NNk67HD7TiIqB40=</wsse:Password>`,
		`<wsse:Nonce EncodingType="` + Base64BinaryURI + `">AAECAwQFBgcICQoLDA0ODw==</wsse:Nonce>`,
		`<wsu:Created>2026-01-02T03:04:05.000Z</wsu:Created>`,
		`<wsu:Expires>2026-01-02T03:05:05.000Z</wsu:Expires>`,
		`soapenv:mustUnderstand="true"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("header missing %s\n%s", want, h)
		}
	}
	if err := CheckFragment(h); err != nil {
		t.Fatal(err)
	}
}

func TestFaults(t *testing.T) {
	f11 := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault>
<faultcode>soap:Client</faultcode><faultstring>Bad city</faultstring><faultactor>urn:weather</faultactor>
<detail><w:ForecastFault xmlns:w="http://example.com/weather"><w:code>404</w:code><w:message>unknown</w:message></w:ForecastFault></detail>
</soap:Fault></soap:Body></soap:Envelope>`
	r, err := ParseResponse([]byte(f11), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "fault11.json", r.Fault)

	f12 := `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:m="urn:m"><env:Body><env:Fault>
<env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>m:BadArgs</env:Value><env:Subcode><env:Value>m:TooSmall</env:Value></env:Subcode></env:Subcode></env:Code>
<env:Reason><env:Text xml:lang="en">Bad arguments</env:Text><env:Text xml:lang="nl">Foute argumenten</env:Text></env:Reason>
<env:Node>http://node</env:Node><env:Role>http://role</env:Role>
<env:Detail><m:Info a="1">x</m:Info></env:Detail>
</env:Fault></env:Body></env:Envelope>`
	r, err = ParseResponse([]byte(f12), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "fault12.json", r.Fault)
}

func TestXMLToJSONGolden(t *testing.T) {
	defs := loadFixture(t, "weather.wsdl")
	o, err := defs.FindOperation("GetForecast", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("testdata", "xml2json", "forecast-response.xml"))
	if err != nil {
		t.Fatal(err)
	}
	typed, err := ParseResponse(data, defs.OutputFields(o), false)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "xml2json-forecast-typed.json", map[string]any{"header": typed.Header, "body": typed.Body})
	untyped, err := ParseResponse(data, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "xml2json-forecast-untyped.json", untyped.Body)

	data, err = os.ReadFile(filepath.Join("testdata", "xml2json", "generic.xml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseResponse(data, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if g.SOAPVersion != "1.2" {
		t.Fatalf("version %s", g.SOAPVersion)
	}
	golden(t, "xml2json-generic.json", g.Body)
}

func TestRecursiveSchema(t *testing.T) {
	wsdl := `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:t="urn:t" targetNamespace="urn:t">
  <types><xs:schema targetNamespace="urn:t" elementFormDefault="qualified">
    <xs:complexType name="Node"><xs:sequence>
      <xs:element name="name" type="xs:string"/>
      <xs:element name="child" type="t:Node" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence></xs:complexType>
    <xs:element name="Tree" type="t:Node"/>
  </xs:schema></types>
  <message name="m"><part name="p" element="t:Tree"/></message>
  <portType name="pt"><operation name="Put"><input message="t:m"/></operation></portType>
  <binding name="b" type="t:pt"><soap:binding style="document"/>
    <operation name="Put"><soap:operation soapAction=""/><input><soap:body use="literal"/></input></operation></binding>
</definitions>`
	defs, err := Load(context.Background(), []byte(wsdl), Location{}, nil, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	desc, err := defs.Describe("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(desc.Operations)
	if !strings.Contains(string(b), `"child?":["recursive: Node"]`) {
		t.Fatalf("recursion not marked: %s", b)
	}
	// The builder expands recursive types on demand.
	args := map[string]any{"name": "root", "child": []any{map[string]any{"name": "a", "child": []any{map[string]any{"name": "b"}}}}}
	p, root := buildEnvelope(t, defs, "Put", args, "")
	tree := bodyChild(t, root)
	if c := tree.Child("urn:t", "child"); c == nil || c.Child("urn:t", "child") == nil || c.Child("urn:t", "child").Child("urn:t", "name").Text != "b" {
		t.Fatalf("recursive build failed\n%s", p.Envelope)
	}
	if p.Op.Address != "" || p.Op.Service != unboundService {
		t.Fatalf("unbound binding: %+v", p.Op)
	}
}

func TestEncodedRPC(t *testing.T) {
	wsdl := `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:t="urn:t" targetNamespace="urn:t">
  <message name="in"><part name="x" type="xsd:int"/></message>
  <message name="out"><part name="y" type="xsd:boolean"/></message>
  <portType name="pt"><operation name="Check"><input message="t:in"/><output message="t:out"/></operation></portType>
  <binding name="b" type="t:pt"><soap:binding style="rpc"/>
    <operation name="Check"><soap:operation soapAction="urn:check"/>
      <input><soap:body use="encoded" namespace="urn:svc" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/></input>
      <output><soap:body use="encoded" namespace="urn:svc" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/></output>
    </operation></binding>
  <service name="s"><port name="p" binding="t:b"><soap:address location="http://x/"/></port></service>
</definitions>`
	defs, err := Load(context.Background(), []byte(wsdl), Location{}, nil, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, root := buildEnvelope(t, defs, "Check", map[string]any{"x": 5.0}, "")
	w := bodyChild(t, root)
	if es, _ := w.LookupAttr(NSSOAP11Env, "encodingStyle"); es != NSSOAPEnc {
		t.Fatalf("encodingStyle missing\n%s", p.Envelope)
	}
	x := w.Child("", "x")
	if xt, _ := x.LookupAttr(NSXSI, "type"); x.ResolveQName(xt) != (QName{Space: NSXSD, Local: "int"}) {
		t.Fatalf("xsi:type missing\n%s", p.Envelope)
	}
	resp := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><n:CheckResult xmlns:n="urn:svc"><y>true</y></n:CheckResult></s:Body></s:Envelope>`
	r, err := ParseResponse([]byte(resp), defs.OutputFields(p.Op), true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.Body)
	if string(b) != `{"CheckResult":{"y":true}}` {
		t.Fatalf("typed rpc response = %s", b)
	}
}

func TestActionQuoting(t *testing.T) {
	action := `urn:a"b\c`
	for _, v := range []string{"1.1", "1.2"} {
		p, err := Prepare(PrepareOptions{RawBody: `<m:Ping xmlns:m="urn:m"/>`, Version: v, SOAPAction: &action})
		if err != nil {
			t.Fatal(err)
		}
		if v == "1.1" {
			if got := p.SOAPActionHeader(); got != `"urn:a\"b\\c"` {
				t.Fatalf("SOAPAction = %s", got)
			}
			continue
		}
		_, params, err := mime.ParseMediaType(p.ContentType)
		if err != nil || params["action"] != action {
			t.Fatalf("Content-Type %q: %v %v", p.ContentType, params, err)
		}
	}
}

func TestRawEnvelopeMalformed(t *testing.T) {
	for _, raw := range []string{
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`,
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body></s:Body></s:Envelope><extra/>`,
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header/></s:Envelope>`,
	} {
		if _, err := Prepare(PrepareOptions{RawBody: raw}); err == nil {
			t.Errorf("malformed envelope accepted: %s", raw)
		}
	}
}
