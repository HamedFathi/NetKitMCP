package lowtools_test

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/lowtools"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func echo(c net.Conn) { io.Copy(c, c) }

func TestTCPEchoDelimiter(t *testing.T) {
	host, port := listen(t, echo)
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "data": `PING\r\nextra`, "escapes": true, "delimiter": `\r\n`,
	})
	if r.Data["data"] != "PING\r\n" || r.Data["ended_by"] != "delimiter" || r.Data["encoding"] != "text" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	if num(r.Data["bytes_sent"]) != 11 {
		t.Fatalf("bytes_sent: %v", r.Data["bytes_sent"])
	}
	timing := r.Data["timing_ms"].(map[string]any)
	if _, ok := timing["first_byte"]; !ok {
		t.Fatalf("missing first_byte timing: %s", r.Raw)
	}
}

func TestTCPHexAndLength(t *testing.T) {
	// A length protocol: the server replies with a fixed 16-byte frame and keeps the connection open.
	host, port := listen(t, func(c net.Conn) {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		c.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
		time.Sleep(2 * time.Second)
	})
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "data": "01 02 03 04", "encoding": "hex", "read_bytes": 4, "output": "hex", "hex_preview": true,
	})
	if r.Data["data"] != "deadbeef" || r.Data["ended_by"] != "length" || r.Data["encoding"] != "hex" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	if !strings.Contains(r.Data["hex_preview"].(string), "de ad be ef") {
		t.Fatalf("hex preview: %v", r.Data["hex_preview"])
	}
	// delimiter_hex stops right after 0x03.
	r = h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "data": "AQIDBA==", "encoding": "base64", "delimiter_hex": "0203", "output": "base64",
	})
	if r.Data["ended_by"] != "delimiter" || r.Data["data"] != "3q2+7wABAgM=" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
}

func TestTCPHalfCloseAndPeerClose(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		b, _ := io.ReadAll(c)
		fmt.Fprintf(c, "got %d bytes", len(b))
	})
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tcp_request", map[string]any{"host": host, "port": port, "data": "hello world", "half_close": true})
	if r.Data["data"] != "got 11 bytes" || r.Data["ended_by"] != "peer_closed" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
}

func TestTCPFileStreamAndTruncation(t *testing.T) {
	host, port := listen(t, echo)
	h := tooltest.New(t, "lowlevel")
	data := make([]byte, 300<<10)
	for i := range data {
		data[i] = byte(i % 251)
	}
	path := h.WriteInput("blob.bin", data)
	sum := sha256.Sum256(data)
	r := h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "file": path, "half_close": true, "max_response_bytes": 1 << 20,
	})
	if num(r.Data["bytes_sent"]) != float64(len(data)) || num(r.Data["bytes_received"]) != float64(len(data)) {
		t.Fatalf("sizes: %s", r.Raw[:300])
	}
	if r.Data["encoding"] != "base64" || r.Data["ended_by"] != "peer_closed" {
		t.Fatalf("unexpected encoding/ended_by: %v %v", r.Data["encoding"], r.Data["ended_by"])
	}
	f := r.Data["file"].(map[string]any)
	if f["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("file hash: %v", f)
	}
	// Truncation via max_response_bytes.
	r = h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "file": path, "max_response_bytes": 1000,
	})
	if r.Data["ended_by"] != "max_bytes" || r.Data["truncated"] != true {
		t.Fatalf("unexpected: ended_by=%v truncated=%v", r.Data["ended_by"], r.Data["truncated"])
	}
}

func TestTCPIdleBanner(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		c.Write([]byte("220 hello\r\n"))
		time.Sleep(3 * time.Second)
	})
	h := tooltest.New(t, "lowlevel")
	start := time.Now()
	r := h.MustOK("tcp_request", map[string]any{"host": host, "port": port, "read_timeout_seconds": 0.3})
	if r.Data["data"] != "220 hello\r\n" || r.Data["ended_by"] != "idle" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("idle timeout not honored")
	}
}

func TestTCPOverallTimeout(t *testing.T) {
	host, port := listen(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tcp_request", map[string]any{"host": host, "port": port, "delimiter": "\n", "timeout_seconds": 0.5})
	if r.Data["ended_by"] != "timeout" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
}

func TestTCPTLS(t *testing.T) {
	ca := newCA(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{ca.validLeaf(t)}, NextProtos: []string{"echo/1"}}
	host, port := listenTLS(t, cfg, func(c net.Conn) {
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("TLS:" + line))
	})
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("tcp_request", map[string]any{
		"host": host, "port": port, "tls": true, "ca_cert": ca.PEM, "server_name": "localhost",
		"alpn": []string{"echo/1"}, "data": "hi\n", "delimiter": "\n",
	})
	if r.Data["data"] != "TLS:hi\n" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	ti := r.Data["tls"].(map[string]any)
	if ti["version"] != "TLS 1.3" || ti["alpn"] != "echo/1" || ti["peer_cn"] != "localhost" {
		t.Fatalf("tls info: %v", ti)
	}
	// Untrusted certificate fails the handshake without ca_cert.
	h.MustFail("tcp_request", map[string]any{"host": host, "port": port, "tls": true, "data": "x\n"}, "certificate")
	// insecure_skip_verify works and is flagged.
	r = h.MustOK("tcp_request", map[string]any{"host": host, "port": port, "tls": true, "insecure_skip_verify": true, "data": "x\n", "delimiter": "\n"})
	if !strings.Contains(fmt.Sprint(r.Data["warnings"]), "insecure_skip_verify") {
		t.Fatalf("missing warning: %s", r.Raw)
	}
}

func TestTCPPortAllowlist(t *testing.T) {
	host, port := listen(t, echo)
	h := tooltest.New(t, "lowlevel", withAllowPorts(port+1))
	h.MustFail("tcp_request", map[string]any{"host": host, "port": port, "data": "x"}, "port allow list")
	h2 := tooltest.New(t, "lowlevel", withAllowPorts(port))
	h2.MustOK("tcp_request", map[string]any{"host": host, "port": port, "data": "x\n", "delimiter": "\n"})
}

func TestTCPSSRFGuard(t *testing.T) {
	host, port := listen(t, echo)
	h := tooltest.New(t, "lowlevel", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("tcp_request", map[string]any{"host": host, "port": port, "data": "x"}, "allow_private")
	h.MustFail("tcp_request", map[string]any{"host": "localhost", "port": port, "data": "x"}, "allow_private")
	h.MustOK("tcp_request", map[string]any{"host": host, "port": port, "data": "x\n", "delimiter": "\n", "allow_private": true})
}

func TestTCPValidation(t *testing.T) {
	h := tooltest.New(t, "lowlevel")
	h.MustFail("tcp_request", map[string]any{"host": "127.0.0.1"}, "port is required")
	h.MustFail("tcp_request", map[string]any{"host": "http://example.com", "port": 80}, "not a URL")
	h.MustFail("tcp_request", map[string]any{"host": "127.0.0.1", "port": 1, "data": "zz", "encoding": "hex"}, "hex")
	h.MustFail("tcp_request", map[string]any{"host": "127.0.0.1", "port": 1, "file": "/etc/passwd"}, "")
}
