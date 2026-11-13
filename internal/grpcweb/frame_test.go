package grpcweb

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msgs := [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte{0xff}, 70000)}
	for _, m := range msgs {
		if err := WriteFrame(&buf, FlagData, m); err != nil {
			t.Fatal(err)
		}
	}
	tr := http.Header{}
	tr.Set("Grpc-Status", "0")
	tr.Add("X-Multi", "a")
	tr.Add("X-Multi", "b")
	buf.Write(EncodeFrame(FlagTrailer, EncodeTrailers(tr)))

	r := bytes.NewReader(buf.Bytes())
	for i, want := range msgs {
		f, err := ReadFrame(r, 0)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.IsTrailer() || !bytes.Equal(f.Data, want) {
			t.Fatalf("frame %d mismatch: flag=%x len=%d", i, f.Flag, len(f.Data))
		}
	}
	f, err := ReadFrame(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsTrailer() {
		t.Fatalf("expected trailers frame, flag=%x", f.Flag)
	}
	got, err := ParseTrailers(f.Data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("grpc-status") != "0" || strings.Join(got.Values("x-multi"), ",") != "a,b" {
		t.Fatalf("trailers = %v", got)
	}
	if string(EncodeTrailers(tr)) != "grpc-status: 0\r\nx-multi: a\r\nx-multi: b\r\n" {
		t.Fatalf("trailer encoding = %q", EncodeTrailers(tr))
	}
	if _, err := ReadFrame(r, 0); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestFrameErrors(t *testing.T) {
	full := EncodeFrame(FlagData, []byte("abcdef"))
	if _, err := ReadFrame(bytes.NewReader(full[:7]), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(full), 3); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(full[:2]), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short header: %v", err)
	}
}

func TestDecompress(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write([]byte("compressed payload"))
	zw.Close()
	f := Frame{Flag: FlagCompressed, Data: zb.Bytes()}
	out, err := Decompress(f, "gzip", 0)
	if err != nil || string(out) != "compressed payload" {
		t.Fatalf("decompress = %q, %v", out, err)
	}
	if _, err := Decompress(f, "", 0); err == nil {
		t.Fatal("expected error without negotiated encoding")
	}
	if _, err := Decompress(f, "gzip", 4); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestTextReaderConcatenatedChunks(t *testing.T) {
	a := EncodeFrame(FlagData, []byte("x"))                     // 6 bytes -> padded
	b := EncodeFrame(FlagTrailer, []byte("grpc-status: 0\r\n")) // 21 bytes -> padded
	body := base64.StdEncoding.EncodeToString(a) + "\r\n" + base64.StdEncoding.EncodeToString(b)
	r := NewTextReader(strings.NewReader(body))
	f1, err := ReadFrame(r, 0)
	if err != nil || string(f1.Data) != "x" {
		t.Fatalf("f1 = %+v, %v", f1, err)
	}
	f2, err := ReadFrame(r, 0)
	if err != nil || !f2.IsTrailer() {
		t.Fatalf("f2 = %+v, %v", f2, err)
	}
	if _, err := ReadFrame(r, 0); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	if string(EncodeText([]byte{1, 2, 3, 4})) != "AQIDBA==" {
		t.Fatal("EncodeText")
	}
}

func TestGRPCMessageEncoding(t *testing.T) {
	in := "bad request: 100% \"wrong\" ünïcode\n"
	enc := EncodeGRPCMessage(in)
	if strings.ContainsAny(enc, "\n ü") && strings.Contains(enc, "\n") {
		t.Fatalf("not encoded: %q", enc)
	}
	if got := DecodeGRPCMessage(enc); got != in {
		t.Fatalf("round trip = %q", got)
	}
	if EncodeTimeout(1500*time.Millisecond) != "1500m" {
		t.Fatal(EncodeTimeout(1500 * time.Millisecond))
	}
	h := http.Header{}
	h.Set("grpc-status", "5")
	h.Set("grpc-message", "not%20found")
	h.Set("grpc-status-details-bin", base64.RawStdEncoding.EncodeToString([]byte{8, 5}))
	st := StatusFromHeader(h)
	if st == nil || st.Code != 5 || st.Message != "not found" || !bytes.Equal(st.DetailsBin, []byte{8, 5}) {
		t.Fatalf("status = %+v", st)
	}
}

func TestCallAgainstHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		text := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web-text")
		var body io.Reader = r.Body
		if text {
			body = NewTextReader(r.Body)
		}
		f, err := ReadFrame(body, 0)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var out bytes.Buffer
		for i := 0; i < 3; i++ {
			out.Write(EncodeFrame(FlagData, append([]byte("echo:"), f.Data...)))
		}
		tr := http.Header{}
		tr.Set("grpc-status", "0")
		tr.Set("x-trailer", "t")
		out.Write(EncodeFrame(FlagTrailer, EncodeTrailers(tr)))
		data := out.Bytes()
		if text {
			w.Header().Set("Content-Type", ContentTypeText)
			data = EncodeText(data)
		} else {
			w.Header().Set("Content-Type", ContentTypeProto)
		}
		w.Write(data)
	}))
	defer srv.Close()
	for _, text := range []bool{false, true} {
		var got []string
		res, err := Call(context.Background(), srv.Client(), Request{URL: srv.URL + "/a.B/C", Text: text, Message: []byte("hi")},
			func(b []byte) bool { got = append(got, string(b)); return true })
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0] != "echo:hi" || res.Status == nil || res.Status.Code != 0 || res.Trailer.Get("x-trailer") != "t" {
			t.Fatalf("text=%v got=%v res=%+v", text, got, res)
		}
		// Stop early.
		res, err = Call(context.Background(), srv.Client(), Request{URL: srv.URL + "/a.B/C", Text: text, Message: []byte("hi")},
			func(b []byte) bool { return false })
		if err != nil || !res.Stopped || res.Messages != 1 {
			t.Fatalf("stop: %+v %v", res, err)
		}
	}
}
