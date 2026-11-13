package lowtools_test

import (
	"net"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// udpServer replies to each datagram with `replies` copies prefixed by an index.
func udpServer(t *testing.T, replies int) (string, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for i := 0; i < replies; i++ {
				pc.WriteTo(append([]byte{byte('0' + i), ':'}, buf[:n]...), from)
			}
		}
	}()
	return splitAddr(t, pc.LocalAddr().String())
}

func TestUDPEcho(t *testing.T) {
	host, port := udpServer(t, 1)
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("udp_request", map[string]any{"host": host, "port": port, "data": "ping"})
	resp := r.Data["responses"].([]any)
	if len(resp) != 1 || r.Data["ended_by"] != "max_responses" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	first := resp[0].(map[string]any)
	if first["data"] != "0:ping" || first["from"] == "" || num(first["size_bytes"]) != 6 {
		t.Fatalf("reply: %v", first)
	}
}

func TestUDPMultipleAndTimeout(t *testing.T) {
	host, port := udpServer(t, 3)
	h := tooltest.New(t, "lowlevel")
	r := h.MustOK("udp_request", map[string]any{"host": host, "port": port, "data": "AAE=", "encoding": "base64",
		"max_responses": 5, "wait_seconds": 0.5, "output": "hex"})
	resp := r.Data["responses"].([]any)
	if len(resp) != 3 || r.Data["ended_by"] != "timeout" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
	if resp[2].(map[string]any)["data"] != "323a0001" {
		t.Fatalf("hex reply: %v", resp[2])
	}

	// A silent server: no replies, ended_by timeout.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	sh, sp := splitAddr(t, silent.LocalAddr().String())
	r = h.MustOK("udp_request", map[string]any{"host": sh, "port": sp, "data": "x", "wait_seconds": 0.3})
	if len(r.Data["responses"].([]any)) != 0 || r.Data["ended_by"] != "timeout" {
		t.Fatalf("unexpected: %s", r.Raw)
	}
}

func TestUDPGuard(t *testing.T) {
	host, port := udpServer(t, 1)
	h := tooltest.New(t, "lowlevel", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("udp_request", map[string]any{"host": host, "port": port, "data": "x"}, "allow_private")
	h.MustOK("udp_request", map[string]any{"host": host, "port": port, "data": "x", "allow_private": true})
	hp := tooltest.New(t, "lowlevel", withAllowPorts(53))
	hp.MustFail("udp_request", map[string]any{"host": host, "port": port, "data": "x"}, "port allow list")
}
