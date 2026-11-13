package connectrpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/grpcweb"
)

func TestStreamEdgeCases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connect-Timeout-Ms") != "1500" || r.Header.Get("Content-Type") != "application/connect+proto" {
			http.Error(w, "bad request headers: "+r.Header.Get("Content-Type"), 400)
			return
		}
		w.Header().Set("Content-Type", "application/connect+proto")
		switch r.URL.Path {
		case "/no-end":
			w.Write(grpcweb.EncodeFrame(0, []byte("a")))
		case "/error":
			w.Write(grpcweb.EncodeFrame(0, []byte("a")))
			w.Write(grpcweb.EncodeFrame(grpcweb.FlagEndStream, []byte(`{"error":{"message":"boom"},"metadata":{"x-k":["v"]}}`)))
		case "/gzip":
			w.Header().Set("Connect-Content-Encoding", "gzip")
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write([]byte("zipped"))
			zw.Close()
			w.Write(grpcweb.EncodeFrame(grpcweb.FlagCompressed, b.Bytes()))
			w.Write(EncodeEndStream(EndStream{}))
		case "/bad-end":
			w.Write(grpcweb.EncodeFrame(grpcweb.FlagEndStream, []byte(`{not json`)))
		case "/many":
			for i := 0; i < 5; i++ {
				w.Write(grpcweb.EncodeFrame(0, []byte("m")))
			}
			w.Write(EncodeEndStream(EndStream{}))
		}
	}))
	defer srv.Close()
	call := func(p string, stop int) (*Result, []string, error) {
		var got []string
		res, err := Call(context.Background(), srv.Client(), Request{URL: srv.URL + p, Codec: CodecProto, Streaming: true, Timeout: 1500 * time.Millisecond},
			func(b []byte) bool { got = append(got, string(b)); return stop == 0 || len(got) < stop })
		return res, got, err
	}
	res, got, err := call("/no-end", 0)
	if err != nil || res.Error == nil || res.Error.Code != "unknown" || len(got) != 1 {
		t.Fatalf("no end: %+v %v %v", res, got, err)
	}
	res, _, err = call("/error", 0)
	if err != nil || res.Error == nil || res.Error.Code != "unknown" || res.Error.Message != "boom" || res.Trailer.Get("X-K") != "v" {
		t.Fatalf("error: %+v %v", res, err)
	}
	res, got, err = call("/gzip", 0)
	if err != nil || res.Error != nil || len(got) != 1 || got[0] != "zipped" {
		t.Fatalf("gzip: %+v %v %v", res, got, err)
	}
	if _, _, err = call("/bad-end", 0); err == nil || !strings.Contains(err.Error(), "end-of-stream") {
		t.Fatalf("bad end: %v", err)
	}
	res, got, err = call("/many", 2)
	if err != nil || !res.Stopped || len(got) != 2 {
		t.Fatalf("stop: %+v %v %v", res, got, err)
	}
	if _, err := Call(context.Background(), srv.Client(), Request{URL: srv.URL, Codec: "xml"}, nil); err == nil {
		t.Fatal("bad codec accepted")
	}
	if ContentType("", false) != "application/json" || ContentType(CodecProto, true) != "application/connect+proto" {
		t.Fatal("content types")
	}
}
