package rpcx

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBuildRequestsAutoID(t *testing.T) {
	reqs, err := BuildRequests([]Call{
		{Method: "a"},
		{Method: "b", ID: float64(1)},
		{Method: "c", Notification: true, Params: []any{1}},
		{Method: "d", Params: map[string]any{"x": 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reqs[0].ID != int64(2) || reqs[1].ID != float64(1) || reqs[2].ID != nil || reqs[3].ID != int64(3) {
		t.Fatalf("ids: %v %v %v %v", reqs[0].ID, reqs[1].ID, reqs[2].ID, reqs[3].ID)
	}
	b, _ := Encode(reqs, true)
	if !strings.Contains(string(b), `{"jsonrpc":"2.0","method":"c","params":[1]}`) {
		t.Fatalf("notification should have no id: %s", b)
	}
	if _, err := BuildRequests([]Call{{Method: "x", Params: "scalar"}}); err == nil {
		t.Fatal("scalar params should be rejected")
	}
}

func TestParseResponses(t *testing.T) {
	rs, batch, err := ParseResponses([]byte(`[{"jsonrpc":"2.0","id":1,"result":null},{"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"Method not found"}}]`))
	if err != nil || !batch || len(rs) != 2 {
		t.Fatal(rs, err)
	}
	if !rs[0].HasResult || rs[0].Result != nil || IDKey(rs[0].ID) != "1" {
		t.Fatalf("%#v", rs[0])
	}
	if rs[1].Error == nil || rs[1].Error.Code != -32601 || IDKey(rs[1].ID) != `"x"` {
		t.Fatalf("%#v", rs[1])
	}
	if StandardErrorName(-32601) != "method not found" {
		t.Fatal()
	}
	if _, _, err := ParseResponses([]byte(`{"jsonrpc":"2.0","id":1}`)); err == nil {
		t.Fatal("expected error for response without result/error")
	}
	rs, _, err = ParseResponses(nil)
	if err != nil || rs != nil {
		t.Fatal(rs, err)
	}
}

func TestXMLRPCEncode(t *testing.T) {
	params := []any{
		"a<b", float64(42), 3.5, true, nil,
		[]any{float64(1), "two"},
		map[string]any{"z": float64(1), "a": "x"},
		map[string]any{"$type": "base64", "value": "aGVsbG8="},
		map[string]any{"$type": "dateTime.iso8601", "value": "2024-01-02T03:04:05Z"},
		map[string]any{"$type": "double", "value": float64(2)},
		map[string]any{"$type": "i4", "value": "7"},
		map[string]any{"$type": "string", "value": float64(12)},
		float64(1 << 40),
	}
	b, err := EncodeCall("pkg.method", params, XMLRPCOptions{AllowNil: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>
<methodCall><methodName>pkg.method</methodName><params>` +
		`<param><value><string>a&lt;b</string></value></param>` +
		`<param><value><int>42</int></value></param>` +
		`<param><value><double>3.5</double></value></param>` +
		`<param><value><boolean>1</boolean></value></param>` +
		`<param><value><nil/></value></param>` +
		`<param><value><array><data><value><int>1</int></value><value><string>two</string></value></data></array></value></param>` +
		`<param><value><struct><member><name>a</name><value><string>x</string></value></member><member><name>z</name><value><int>1</int></value></member></struct></value></param>` +
		`<param><value><base64>aGVsbG8=</base64></value></param>` +
		`<param><value><dateTime.iso8601>20240102T03:04:05</dateTime.iso8601></value></param>` +
		`<param><value><double>2</double></value></param>` +
		`<param><value><i4>7</i4></value></param>` +
		`<param><value><string>12</string></value></param>` +
		`<param><value><i8>1099511627776</i8></value></param>` +
		`</params></methodCall>
`
	if string(b) != want {
		t.Fatalf("got\n%s\nwant\n%s", b, want)
	}
	if _, err := EncodeCall("m", []any{nil}, XMLRPCOptions{}); err == nil || !strings.Contains(err.Error(), "allow_nil") {
		t.Fatalf("expected nil error, got %v", err)
	}
	if _, err := EncodeCall("m", []any{map[string]any{"$type": "bogus"}}, XMLRPCOptions{}); err == nil {
		t.Fatal("expected unknown type error")
	}
}

func TestXMLRPCDecode(t *testing.T) {
	doc := `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><struct>
        <member><name>s</name><value>plain default string</value></member>
        <member><name>i</name><value><i4>-3</i4></value></member>
        <member><name>d</name><value><double>1.25</double></value></member>
        <member><name>b</name><value><boolean>0</boolean></value></member>
        <member><name>n</name><value><nil/></value></member>
        <member><name>bin</name><value><base64>aGVs
bG8=</base64></value></member>
        <member><name>t</name><value><dateTime.iso8601>19980717T14:08:55</dateTime.iso8601></value></member>
        <member><name>arr</name><value><array><data><value><int>1</int></value><value><string>x</string></value></data></array></value></member>
        <member><name>empty</name><value></value></member>
      </struct></value>
    </param>
  </params>
</methodResponse>`
	r, err := DecodeResponse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if r.Fault != nil || len(r.Params) != 1 {
		t.Fatalf("%#v", r)
	}
	got, _ := json.Marshal(r.Params[0])
	want := `{"arr":[1,"x"],"b":false,"bin":{"$type":"base64","value":"aGVsbG8="},"d":1.25,"empty":"","i":-3,"n":null,"s":"plain default string","t":{"$type":"dateTime.iso8601","value":"19980717T14:08:55"}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestXMLRPCFault(t *testing.T) {
	doc := `<?xml version="1.0"?><methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>4</int></value></member>
<member><name>faultString</name><value><string>Too many parameters.</string></value></member>
</struct></value></fault></methodResponse>`
	r, err := DecodeResponse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if r.Fault == nil || r.Fault.FaultCode != int64(4) || r.Fault.FaultString != "Too many parameters." {
		t.Fatalf("%#v", r.Fault)
	}
}

func TestXMLRPCRoundTrip(t *testing.T) {
	in := []any{map[string]any{
		"bin":  map[string]any{"$type": "base64", "value": "AAEC"},
		"when": map[string]any{"$type": "dateTime.iso8601", "value": "20240102T03:04:05"},
		"list": []any{float64(1), 2.5, "s", false},
	}}
	b, err := EncodeCall("echo", in, XMLRPCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Turn the call into a response and decode it back.
	s := string(b)
	s = s[strings.Index(s, "<params>"):strings.Index(s, "</methodCall>")]
	r, err := DecodeResponse(strings.NewReader("<methodResponse>" + s + "</methodResponse>"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"bin":  map[string]any{"$type": "base64", "value": "AAEC"},
		"when": map[string]any{"$type": "dateTime.iso8601", "value": "20240102T03:04:05"},
		"list": []any{int64(1), 2.5, "s", false},
	}
	if !reflect.DeepEqual(r.Params[0], want) {
		t.Fatalf("got %#v", r.Params[0])
	}
}
