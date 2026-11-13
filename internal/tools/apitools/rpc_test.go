package apitools_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rpcErr struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
	Name    string `json:"name"`
}

type rpcResp struct {
	ID     any     `json:"id"`
	Method string  `json:"method"`
	OK     bool    `json:"ok"`
	Result any     `json:"result"`
	Error  *rpcErr `json:"error"`
}

type rpcOut struct {
	Status     int       `json:"status"`
	Batch      bool      `json:"batch"`
	Responses  []rpcResp `json:"responses"`
	MissingIDs []any     `json:"missing_ids"`
	Body       string    `json:"body"`
	Warnings   []string  `json:"warnings"`
}

type rpcReqIn struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      json.RawMessage `json:"id"`
}

// jsonrpcServer implements add, echo and fail; it never answers "skip"
// (simulating a lost response) nor notifications. The last raw request body
// is stored in *last.
func jsonrpcServer(t *testing.T, last *string) string {
	answer := func(q rpcReqIn) map[string]any {
		if len(q.ID) == 0 || q.Method == "skip" {
			return nil
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		switch q.Method {
		case "add":
			var p []float64
			json.Unmarshal(q.Params, &p)
			sum := 0.0
			for _, x := range p {
				sum += x
			}
			resp["result"] = sum
		case "echo":
			resp["result"] = q.Params
		case "nil":
			resp["result"] = nil
		case "fail":
			resp["error"] = map[string]any{"code": -32602, "message": "Invalid params", "data": map[string]any{"field": "x"}}
		default:
			resp["error"] = map[string]any{"code": -32601, "message": "Method not found"}
		}
		return resp
	}
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if last != nil {
			*last = string(b)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "content type", 415)
			return
		}
		s := strings.TrimSpace(string(b))
		if strings.HasPrefix(s, "[") {
			var qs []rpcReqIn
			json.Unmarshal(b, &qs)
			out := []any{}
			for _, q := range qs {
				if a := answer(q); a != nil {
					out = append(out, a)
				}
			}
			if len(out) == 0 {
				w.WriteHeader(204)
				return
			}
			writeJSON(w, out)
			return
		}
		var q rpcReqIn
		if err := json.Unmarshal(b, &q); err != nil {
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "Parse error"}})
			return
		}
		if a := answer(q); a != nil {
			writeJSON(w, a)
			return
		}
		w.WriteHeader(204)
	})
	return srv.URL
}

func TestJSONRPCSingle(t *testing.T) {
	h := newHarness(t)
	var last string
	url := jsonrpcServer(t, &last)

	r := decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "add", "params": []any{1, 2, 3.5}}))
	if r.Batch || len(r.Responses) != 1 || len(r.MissingIDs) != 0 {
		t.Fatalf("%+v", r)
	}
	x := r.Responses[0]
	if !x.OK || x.Method != "add" || x.Result != 6.5 || x.ID != float64(1) {
		t.Fatalf("%+v", x)
	}
	var sent map[string]any
	json.Unmarshal([]byte(last), &sent)
	if sent["jsonrpc"] != "2.0" || sent["id"] != float64(1) || sent["method"] != "add" {
		t.Fatalf("sent %s", last)
	}

	// Named params, string id, null result.
	r = decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "echo", "params": map[string]any{"a": "b"}, "id": "req-7"}))
	if x := r.Responses[0]; !x.OK || x.ID != "req-7" || x.Method != "echo" {
		t.Fatalf("%+v", x)
	}
	mustContain(t, last, `"id":"req-7"`, `"params":{"a":"b"}`)
	r = decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "nil"}))
	if x := r.Responses[0]; !x.OK || x.Result != nil {
		t.Fatalf("%+v", x)
	}
	mustNotContain(t, last, `"params"`)
}

func TestJSONRPCErrorObjectIsResult(t *testing.T) {
	h := newHarness(t)
	url := jsonrpcServer(t, nil)
	r := decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "fail", "params": map[string]any{}}))
	x := r.Responses[0]
	if x.OK || x.Error == nil || x.Error.Code != -32602 || x.Error.Message != "Invalid params" || x.Error.Name != "invalid params" {
		t.Fatalf("%+v", x)
	}
	if m, _ := x.Error.Data.(map[string]any); m["field"] != "x" {
		t.Fatalf("data %v", x.Error.Data)
	}
	r = decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "nope"}))
	if x := r.Responses[0]; x.OK || x.Error.Code != -32601 || x.Error.Name != "method not found" {
		t.Fatalf("%+v", x)
	}
}

func TestJSONRPCBatch(t *testing.T) {
	h := newHarness(t)
	var last string
	url := jsonrpcServer(t, &last)
	r := decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "batch": []any{
		map[string]any{"method": "add", "params": []any{1, 1}},
		map[string]any{"method": "log", "params": []any{"hi"}, "notification": true},
		map[string]any{"method": "fail", "params": []any{}, "id": "f"},
		map[string]any{"method": "skip", "params": []any{}},
		map[string]any{"method": "echo", "params": []any{"x"}, "id": 1}, // explicit id 1 forces auto ids to skip it
	}}))
	if !r.Batch {
		t.Fatalf("%+v", r)
	}
	var sent []map[string]any
	if err := json.Unmarshal([]byte(last), &sent); err != nil || len(sent) != 5 {
		t.Fatalf("sent %s", last)
	}
	if _, has := sent[1]["id"]; has {
		t.Fatalf("notification has an id: %s", last)
	}
	if sent[0]["id"] != float64(2) || sent[3]["id"] != float64(3) || sent[4]["id"] != float64(1) {
		t.Fatalf("ids %s", last)
	}
	if len(r.Responses) != 3 {
		t.Fatalf("responses %+v", r.Responses)
	}
	byMethod := map[string]rpcResp{}
	for _, x := range r.Responses {
		byMethod[x.Method] = x
	}
	if x := byMethod["add"]; !x.OK || x.Result != float64(2) {
		t.Fatalf("add %+v", x)
	}
	if x := byMethod["fail"]; x.OK || x.ID != "f" || x.Error.Code != -32602 {
		t.Fatalf("fail %+v", x)
	}
	if x := byMethod["echo"]; !x.OK || x.ID != float64(1) {
		t.Fatalf("echo %+v", x)
	}
	if len(r.MissingIDs) != 1 || r.MissingIDs[0] != float64(3) {
		t.Fatalf("missing %v", r.MissingIDs)
	}

	// All notifications: no responses, nothing missing.
	r = decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "batch": []any{
		map[string]any{"method": "a", "notification": true},
		map[string]any{"method": "b", "notification": true},
	}}))
	if r.Status != 204 || len(r.Responses) != 0 || len(r.MissingIDs) != 0 {
		t.Fatalf("%+v", r)
	}
	// Single notification.
	r = decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": url, "method": "log", "notification": true}))
	if len(r.Responses) != 0 || len(r.MissingIDs) != 0 {
		t.Fatalf("%+v", r)
	}
	mustNotContain(t, last, `"id"`)
}

func TestJSONRPCBadResponses(t *testing.T) {
	h := newHarness(t)
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(500)
		io.WriteString(w, "<html>oops</html>")
	})
	r := decode[rpcOut](t, h.MustOK("jsonrpc_request", map[string]any{"url": srv.URL, "method": "x"}))
	if r.Status != 500 || r.Body != "<html>oops</html>" || len(r.Responses) != 0 || len(r.Warnings) < 2 {
		t.Fatalf("%+v", r)
	}
	if len(r.MissingIDs) != 0 {
		// The body could not be parsed, so nothing can be said about ids.
		t.Logf("missing ids %v", r.MissingIDs)
	}
	h.MustFail("jsonrpc_request", map[string]any{"url": srv.URL}, "method is required")
	h.MustFail("jsonrpc_request", map[string]any{"url": srv.URL, "method": "a", "batch": []any{map[string]any{"method": "b"}}}, "not both")
	h.MustFail("jsonrpc_request", map[string]any{"url": srv.URL, "method": "a", "params": "scalar"}, "object or an array")
}

const xmlFault = `<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>4</int></value></member>
<member><name>faultString</name><value><string>Too many parameters.</string></value></member>
</struct></value></fault></methodResponse>`

type xmlOut struct {
	Status int   `json:"status"`
	OK     bool  `json:"ok"`
	Result any   `json:"result"`
	Params []any `json:"params"`
	Fault  *struct {
		FaultCode   any    `json:"faultCode"`
		FaultString string `json:"faultString"`
	} `json:"fault"`
	Body     string   `json:"body"`
	Warnings []string `json:"warnings"`
}

func TestXMLRPC(t *testing.T) {
	h := newHarness(t)
	var got string
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "text/xml") {
			http.Error(w, "ct", 415)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.Contains(got, "<methodName>fault</methodName>"):
			io.WriteString(w, xmlFault)
		case strings.Contains(got, "<methodName>garbage</methodName>"):
			io.WriteString(w, "this is not xml")
		default:
			io.WriteString(w, `<?xml version="1.0"?><methodResponse><params><param><value><struct>
<member><name>sum</name><value><i4>7</i4></value></member>
<member><name>name</name><value>plain string</value></member>
<member><name>ok</name><value><boolean>1</boolean></value></member>
<member><name>list</name><value><array><data><value><double>1.5</double></value><value><string>x</string></value></data></array></value></member>
</struct></value></param></params></methodResponse>`)
		}
	})

	r := decode[xmlOut](t, h.MustOK("xmlrpc_request", map[string]any{
		"url": srv.URL, "method": "sample.add",
		"params": []any{3, 4.25, "a<b", true, []any{1, "x"}, map[string]any{"k": 1},
			map[string]any{"$type": "base64", "value": "aGVsbG8="}, nil},
		"allow_nil": true,
	}))
	mustContain(t, got, "<methodName>sample.add</methodName>", "<int>3</int>", "<double>4.25</double>",
		"<string>a&lt;b</string>", "<boolean>1</boolean>", "<array><data>", "<struct><member><name>k</name>",
		"<base64>aGVsbG8=</base64>", "<nil/>")
	if r.Status != 200 || !r.OK || r.Fault != nil {
		t.Fatalf("%+v", r)
	}
	m, _ := r.Result.(map[string]any)
	if m["sum"] != float64(7) || m["name"] != "plain string" || m["ok"] != true {
		t.Fatalf("result %#v", r.Result)
	}
	if l, _ := m["list"].([]any); len(l) != 2 || l[0] != 1.5 || l[1] != "x" {
		t.Fatalf("list %#v", m["list"])
	}

	r = decode[xmlOut](t, h.MustOK("xmlrpc_request", map[string]any{"url": srv.URL, "method": "fault", "params": []any{1}}))
	if r.OK || r.Fault == nil || r.Fault.FaultString != "Too many parameters." || r.Fault.FaultCode != float64(4) {
		t.Fatalf("%+v", r)
	}

	r = decode[xmlOut](t, h.MustOK("xmlrpc_request", map[string]any{"url": srv.URL, "method": "garbage"}))
	if r.OK || r.Body != "this is not xml" || len(r.Warnings) == 0 {
		t.Fatalf("%+v", r)
	}

	h.MustFail("xmlrpc_request", map[string]any{"url": srv.URL, "method": "x", "params": []any{nil}}, "allow_nil")
	h.MustFail("xmlrpc_request", map[string]any{"url": srv.URL, "method": ""}, "method is required")
}
