package ftpx

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/ftpx/ftptest"
)

// publicIP stands in for a public FTP server: the fake network below routes
// it (and the name ftp.example.test) to the loopback test server, while
// every other address goes through the real SSRF guard with allow_private
// off, as it would for a public target.
const publicIP = "198.51.100.7"

type remoteAs struct {
	net.Conn
	ip net.IP
}

func (c remoteAs) RemoteAddr() net.Addr {
	a := c.Conn.RemoteAddr().(*net.TCPAddr)
	return &net.TCPAddr{IP: c.ip, Port: a.Port}
}

type fakeNet struct {
	mu     sync.Mutex
	dialed []string
	guard  *netguard.Dialer
}

func newFakeNet() *fakeNet {
	cfg := config.Default() // private mode: opt-in
	return &fakeNet{guard: netguard.New(cfg).Dialer(false, 5*time.Second)}
}

func (n *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "ftp.example.test" || host == publicIP {
		c, err := net.Dial(network, net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			return nil, err
		}
		return remoteAs{c, net.ParseIP(publicIP)}, nil
	}
	return n.guard.DialContext(ctx, network, addr)
}

func (n *fakeNet) Dialed() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

func connectFake(t *testing.T, s *ftptest.Server, n *fakeNet, host string, trust bool) (*Conn, error) {
	t.Helper()
	return Connect(context.Background(), Config{
		Host: host, Port: s.Port, Dial: n.dial, TrustPasvIP: trust,
		Timeout: 5 * time.Second, Idle: 5 * time.Second, User: "u", Password: "p",
	})
}

func TestPasvAddressIsGuarded(t *testing.T) {
	for _, c := range []struct {
		name     string
		host     string
		pasv     string
		trust    bool
		blocked  bool
		wantDial string // expected data dial host
	}{
		// Default: the PASV address is ignored; data goes to the control IP.
		{"untrusted-private", "ftp.example.test", "10.0.0.5", false, false, publicIP},
		{"untrusted-metadata", "ftp.example.test", "169.254.169.254", false, false, publicIP},
		{"untrusted-loopback", publicIP, "127.0.0.1", false, false, publicIP},
		// trust_pasv_ip: a different address is followed, but only through the guard.
		{"trusted-metadata", "ftp.example.test", "169.254.169.254", true, true, "169.254.169.254"},
		{"trusted-cgnat", publicIP, "100.64.1.2", true, true, "100.64.1.2"},
		{"trusted-thisnet", "ftp.example.test", "0.0.0.1", true, true, "0.0.0.1"},
		// The library itself falls back to the control host when the PASV
		// address is private/loopback and the control host is not.
		{"trusted-private-bogus", publicIP, "10.0.0.5", true, false, publicIP},
		{"trusted-loopback-bogus", publicIP, "127.0.0.1", true, false, publicIP},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			os.WriteFile(filepath.Join(root, "f.txt"), []byte("hello"), 0o644)
			s := ftptest.New(t, root, ftptest.Options{NoEPSV: true, PasvIP: c.pasv})
			n := newFakeNet()
			conn, err := connectFake(t, s, n, c.host, c.trust)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.ControlIP() != publicIP {
				t.Fatalf("control IP %s", conn.ControlIP())
			}
			_, err = conn.List(context.Background(), "/", ListOptions{MaxEntries: 10})
			d := n.Dialed()
			if len(d) != 2 {
				t.Fatalf("dials: %v", d)
			}
			if h, _, _ := net.SplitHostPort(d[1]); h != c.wantDial {
				t.Fatalf("data connection dialed %s, want host %s", d[1], c.wantDial)
			}
			if c.blocked {
				if err == nil || !errors.Is(err, netguard.ErrBlocked) && !strings.Contains(err.Error(), netguard.ErrBlocked.Error()) {
					t.Fatalf("PASV to %s must be blocked by the guard, got %v", c.pasv, err)
				}
				if s.DataConns() != 0 || conn.DataConns() != 0 {
					t.Fatal("a blocked data connection was opened")
				}
				return
			}
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if s.DataConns() != 1 || conn.DataConns() != 1 {
				t.Fatalf("data conns: server %d client %d", s.DataConns(), conn.DataConns())
			}
		})
	}
}

// TestDataDialPinnedToControlIP covers ftpx's own check, independent of the
// library: without TrustPasvIP a data dial to any other host is refused
// before dialing.
func TestDataDialPinnedToControlIP(t *testing.T) {
	root := t.TempDir()
	s := ftptest.New(t, root, ftptest.Options{})
	n := newFakeNet()
	conn, err := connectFake(t, s, n, "ftp.example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	before := len(n.Dialed())
	for _, addr := range []string{"10.0.0.5:2000", "203.0.113.9:2000", "ftp.example.test:2000"} {
		if _, err := conn.dial("tcp", addr); err == nil || !errors.Is(err, netguard.ErrBlocked) || !strings.Contains(err.Error(), "trust_pasv_ip") {
			t.Fatalf("data dial to %s: %v", addr, err)
		}
	}
	if len(n.Dialed()) != before {
		t.Fatalf("refused data connections were dialed: %v", n.Dialed()[before:])
	}
}

func TestModes(t *testing.T) {
	for in, want := range map[string]string{"": TLSNone, "off": TLSNone, "explicit": TLSExplicit, "AUTH_TLS": TLSExplicit, "ftps": TLSImplicit} {
		if got := normMode(in); got != want || !ValidMode(in) {
			t.Errorf("normMode(%q) = %q", in, got)
		}
	}
	if ValidMode("bogus") {
		t.Error("bogus mode accepted")
	}
	if DefaultPort("implicit") != 990 || DefaultPort("") != 21 {
		t.Error("default ports")
	}
	if _, err := Connect(context.Background(), Config{TLSMode: "explicit"}); err == nil {
		t.Error("TLS mode without a TLS config accepted")
	}
}
