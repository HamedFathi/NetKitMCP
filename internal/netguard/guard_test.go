package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
)

func TestIsPrivate(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "100.64.0.1", "0.0.0.0", "fd00::1"} {
		if !IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("%s should be private", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestDialBlocksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := config.Default()
	g := New(cfg)
	_, err = g.Dialer(false, time.Second).DialContext(context.Background(), "tcp", ln.Addr().String())
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected blocked, got %v", err)
	}
	// localhost resolves to loopback: blocked by name check and by Control.
	_, err = g.Dialer(false, time.Second).DialContext(context.Background(), "tcp", "localhost:1")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected blocked for localhost, got %v", err)
	}
	c, err := g.Dialer(true, time.Second).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("opt-in should allow: %v", err)
	}
	c.Close()
	cfg.PrivateMode = config.PrivateDeny
	if _, err := g.Dialer(true, time.Second).DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("deny mode should block: %v", err)
	}
}

func TestHostLists(t *testing.T) {
	cfg := config.Default()
	cfg.AllowHosts = []string{"*.example.com", "10.0.0.0/8"}
	cfg.DenyHosts = []string{"bad.example.com"}
	cfg.PrivateMode = config.PrivateAllow
	d := New(cfg).Dialer(false, time.Second)
	if err := d.CheckHost("api.example.com"); err != nil {
		t.Error(err)
	}
	if err := d.CheckHost("example.com"); err != nil {
		t.Error(err)
	}
	if err := d.CheckHost("10.2.3.4"); err != nil {
		t.Error(err)
	}
	if err := d.CheckHost("bad.example.com"); err == nil {
		t.Error("deny list ignored")
	}
	if err := d.CheckHost("other.org"); err == nil {
		t.Error("allow list ignored")
	}
}

func TestRawPorts(t *testing.T) {
	cfg := config.Default()
	cfg.AllowPorts = []int{53}
	g := New(cfg)
	if err := g.RawDialer(false, time.Second).CheckAddress("8.8.8.8:80"); err == nil {
		t.Error("port allow list ignored")
	}
	if err := g.RawDialer(false, time.Second).CheckAddress("8.8.8.8:53"); err != nil {
		t.Error(err)
	}
	if err := g.Dialer(false, time.Second).CheckAddress("8.8.8.8:80"); err != nil {
		t.Error("non-raw dialer must not apply port list", err)
	}
}
