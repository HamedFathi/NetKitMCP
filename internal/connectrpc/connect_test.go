package connectrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/grpcweb"
)

func TestEndStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(grpcweb.EncodeFrame(grpcweb.FlagData, []byte(`{"n":1}`)))
	buf.Write(EncodeEndStream(EndStream{
		Error:    &Error{Code: "not_found", Message: "gone", Details: []ErrorDetail{{Type: "google.rpc.ErrorInfo", Value: "CgNmb28"}}},
		Metadata: map[string][]string{"x-end": {"a", "b"}},
	}))
	r := bytes.NewReader(buf.Bytes())
	f, err := grpcweb.ReadFrame(r, 0)
	if err != nil || f.IsEndStream() || string(f.Data) != `{"n":1}` {
		t.Fatalf("data frame: %+v %v", f, err)
	}
	f, err = grpcweb.ReadFrame(r, 0)
	if err != nil || !f.IsEndStream() || f.Flag != 0x02 {
		t.Fatalf("end frame: %+v %v", f, err)
	}
	var es EndStream
	if err := json.Unmarshal(f.Data, &es); err != nil {
		t.Fatal(err)
	}
	if es.Error.Code != "not_found" || es.Error.Details[0].Type != "google.rpc.ErrorInfo" || len(es.Metadata["x-end"]) != 2 {
		t.Fatalf("end stream = %+v", es)
	}
}

func TestCodes(t *testing.T) {
	for i := 0; i <= 16; i++ {
		if CodeNumber(CodeName(i)) != i {
			t.Fatalf("code %d round trip", i)
		}
	}
	if CodeNumber("cancelled") != 1 || CodeNumber("bogus") != 2 {
		t.Fatal("aliases")
	}
	if HTTPStatus("not_found") != 404 || HTTPStatus("unauthenticated") != 401 || CodeFromHTTP(503) != "unavailable" {
		t.Fatal("http mapping")
	}
	e := ParseError(502, []byte("<html>bad gateway</html>"))
	if e.Code != "unavailable" {
		t.Fatalf("fallback code = %s", e.Code)
	}
	e = ParseError(404, []byte(`{"code":"not_found","message":"x"}`))
	if e.Code != "not_found" || e.Message != "x" {
		t.Fatalf("parsed = %+v", e)
	}
}

func TestCallUnaryAndStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connect-Protocol-Version") != "1" {
			http.Error(w, "missing protocol version", 400)
			return
		}
		switch r.Header.Get("Content-Type") {
		case "application/json":
			body, _ := io.ReadAll(r.Body)
			if string(body) == `{"fail":true}` {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(HTTPStatus("invalid_argument"))
				w.Write([]byte(`{"code":"invalid_argument","message":"bad"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Trailer-X-T", "tv")
			w.Write(body)
		case "application/connect+json":
			f, err := grpcweb.ReadFrame(r.Body, 0)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			w.Header().Set("Content-Type", "application/connect+json")
			for i := 0; i < 2; i++ {
				w.Write(grpcweb.EncodeFrame(0, f.Data))
			}
			w.Write(EncodeEndStream(EndStream{Metadata: map[string][]string{"x-end": {"yes"}}}))
		default:
			http.Error(w, "unsupported", 415)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	var got []string
	res, err := Call(ctx, srv.Client(), Request{URL: srv.URL + "/a.B/C", Message: []byte(`{"x":1}`)}, func(b []byte) bool { got = append(got, string(b)); return true })
	if err != nil || res.Error != nil || len(got) != 1 || got[0] != `{"x":1}` || res.Trailer.Get("X-T") != "tv" {
		t.Fatalf("unary: %+v %v %v", res, got, err)
	}
	res, err = Call(ctx, srv.Client(), Request{URL: srv.URL + "/a.B/C", Message: []byte(`{"fail":true}`)}, nil)
	if err != nil || res.Error == nil || res.Error.Code != "invalid_argument" || res.HTTPStatus != 400 {
		t.Fatalf("unary error: %+v %v", res, err)
	}
	got = nil
	res, err = Call(ctx, srv.Client(), Request{URL: srv.URL + "/a.B/C", Streaming: true, Message: []byte(`{"s":1}`)}, func(b []byte) bool { got = append(got, string(b)); return true })
	if err != nil || res.Error != nil || len(got) != 2 || res.Trailer.Get("X-End") != "yes" {
		t.Fatalf("stream: %+v %v %v", res, got, err)
	}
}
