package grpcweb

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCallEdgeCases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grpc-Web") != "1" || r.Header.Get("Accept") == "" || r.Header.Get("Grpc-Timeout") != "1500m" {
			http.Error(w, "missing headers", 400)
			return
		}
		switch r.URL.Path {
		case "/trailers-only":
			w.Header().Set("Content-Type", ContentTypeProto)
			w.Header().Set("Grpc-Status", "7")
			w.Header().Set("Grpc-Message", "no%20way")
			w.Header().Set("Grpc-Status-Details-Bin", "CAc") // unpadded base64
		case "/http-trailers":
			w.Header().Set("Content-Type", ContentTypeProto)
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.Write(EncodeFrame(FlagData, []byte("m")))
			w.Header().Set("Grpc-Status", "0")
			w.Header().Set("Grpc-Message", "")
		case "/no-status":
			w.Header().Set("Content-Type", ContentTypeProto)
			w.Write(EncodeFrame(FlagData, []byte("m")))
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html></html>"))
		case "/gzip":
			w.Header().Set("Content-Type", ContentTypeProto)
			w.Header().Set("Grpc-Encoding", "gzip")
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write([]byte("compressed"))
			zw.Close()
			w.Write(EncodeFrame(FlagCompressed, b.Bytes()))
			w.Write(EncodeFrame(FlagTrailer, []byte("grpc-status: 0\r\n")))
		case "/truncated":
			w.Header().Set("Content-Type", ContentTypeProto)
			w.Write(EncodeFrame(FlagData, []byte("abcdef"))[:7])
		case "/503":
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("down"))
		}
	}))
	defer srv.Close()
	call := func(p string) (*Result, []string, error) {
		var got []string
		res, err := Call(context.Background(), srv.Client(), Request{URL: srv.URL + p, Message: []byte("x"), Timeout: 1500 * time.Millisecond},
			func(b []byte) bool { got = append(got, string(b)); return true })
		return res, got, err
	}

	res, got, err := call("/trailers-only")
	if err != nil || res.Status == nil || res.Status.Code != 7 || res.Status.Message != "no way" || len(res.Status.DetailsBin) != 2 || len(got) != 0 {
		t.Fatalf("trailers-only: %+v %v %v", res, got, err)
	}
	res, got, err = call("/http-trailers")
	if err != nil || res.Status == nil || res.Status.Code != 0 || len(got) != 1 {
		t.Fatalf("http trailers: %+v %v %v", res, got, err)
	}
	res, _, err = call("/no-status")
	if err != nil || res.Status == nil || res.Status.Code != 2 || !strings.Contains(res.Status.Message, "grpc-status") {
		t.Fatalf("no status: %+v %v", res, err)
	}
	if _, _, err = call("/html"); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Fatalf("html: %v", err)
	}
	res, got, err = call("/gzip")
	if err != nil || len(got) != 1 || got[0] != "compressed" || res.Status.Code != 0 {
		t.Fatalf("gzip: %+v %v %v", res, got, err)
	}
	if _, _, err = call("/truncated"); err == nil {
		t.Fatalf("truncated frame accepted")
	}
	res, _, err = call("/503")
	if err != nil || res.HTTPStatus != 503 || res.Status.Code != 14 || !strings.Contains(res.Status.Message, "down") {
		t.Fatalf("503: %+v %v", res, err)
	}
}

func TestEncodeTimeoutAndTrailers(t *testing.T) {
	if EncodeTimeout(0) != "1m" || EncodeTimeout(2*time.Second) != "2000m" || EncodeTimeout(48*time.Hour) != "172800S" {
		t.Fatalf("timeouts: %s %s %s", EncodeTimeout(0), EncodeTimeout(2*time.Second), EncodeTimeout(48*time.Hour))
	}
	h, err := ParseTrailers([]byte("grpc-status: 3\r\ngrpc-message: bad%20arg\r\nx-multi: a\r\nx-multi: b\r\n"))
	if err != nil || h.Get("Grpc-Status") != "3" || len(h.Values("X-Multi")) != 2 {
		t.Fatalf("trailers: %v %v", h, err)
	}
	if st := StatusFromHeader(h); st == nil || st.Code != 3 || st.Message != "bad arg" {
		t.Fatalf("status: %+v", st)
	}
	if h, err := ParseTrailers(nil); err != nil || len(h) != 0 {
		t.Fatalf("empty trailers: %v %v", h, err)
	}
	if HTTPToCode(401) != 16 || HTTPToCode(404) != 12 || HTTPToCode(500) != 2 {
		t.Fatal("http to code")
	}
}
