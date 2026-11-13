// Package netguard implements the SSRF guard shared by every protocol.
//
// Hostname allow/deny lists and port allowlists are checked before dialing;
// the resolved IP address is checked inside net.Dialer.Control, which runs
// after DNS resolution for every connection attempt, so DNS rebinding cannot
// bypass the guard.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/config"
)

// ErrBlocked is wrapped by every error the guard returns.
var ErrBlocked = errors.New("blocked by netkit security policy")

// Guard enforces the network policy from config.
type Guard struct {
	cfg *config.Config
}

// New returns a Guard for the given configuration.
func New(cfg *config.Config) *Guard { return &Guard{cfg: cfg} }

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",      // "this" network
		"10.0.0.0/8",     // private
		"100.64.0.0/10",  // carrier-grade NAT
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, incl. cloud metadata 169.254.169.254
		"172.16.0.0/12",  // private
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // private
		"198.18.0.0/15",  // benchmarking
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved + broadcast
		"::/128",         // unspecified
		"::1/128",        // loopback
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
		"64:ff9b::/96",   // NAT64 (may embed private IPv4)
		"64:ff9b:1::/48", // local NAT64
		"2001:db8::/32",  // documentation
		"fec0::/10",      // deprecated site-local
		"100::/64",       // discard
		"2002::/16",      // 6to4 (may embed private IPv4)
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPrivate reports whether ip is in a range blocked by default.
func IsPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Dialer is a per-call guarded dialer.
type Dialer struct {
	g            *Guard
	allowPrivate bool
	rawSocket    bool
	timeout      time.Duration
}

// Dialer returns a guarded dialer. allowPrivate is the per-call opt-in;
// it is honored according to the server's PrivateMode.
func (g *Guard) Dialer(allowPrivate bool, timeout time.Duration) *Dialer {
	return &Dialer{g: g, allowPrivate: g.privateAllowed(allowPrivate), timeout: timeout}
}

// RawDialer is like Dialer but also enforces the port allowlist (used by raw
// TCP/UDP/DNS tools).
func (g *Guard) RawDialer(allowPrivate bool, timeout time.Duration) *Dialer {
	d := g.Dialer(allowPrivate, timeout)
	d.rawSocket = true
	return d
}

func (g *Guard) privateAllowed(optIn bool) bool {
	switch g.cfg.PrivateMode {
	case config.PrivateAllow:
		return true
	case config.PrivateDeny:
		return false
	default:
		return optIn
	}
}

// AllowsPrivate reports whether this dialer may reach private addresses.
func (d *Dialer) AllowsPrivate() bool { return d.allowPrivate }

// Timeout returns the dial timeout.
func (d *Dialer) Timeout() time.Duration { return d.timeout }

// CheckHost checks a bare hostname or IP literal against the allow/deny lists,
// and, for IP literals, against the private-range policy.
func (d *Dialer) CheckHost(host string) error {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if h == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	for _, pat := range d.g.cfg.DenyHosts {
		if matchHost(pat, h) {
			return fmt.Errorf("%w: host %q is on the deny list", ErrBlocked, host)
		}
	}
	if len(d.g.cfg.AllowHosts) > 0 {
		ok := false
		for _, pat := range d.g.cfg.AllowHosts {
			if matchHost(pat, h) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: host %q is not on the allow list", ErrBlocked, host)
		}
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return d.CheckIP(ip)
	}
	if !d.allowPrivate && (h == "localhost" || strings.HasSuffix(h, ".localhost")) {
		return fmt.Errorf("%w: %q is a loopback name (set allow_private=true to permit)", ErrBlocked, host)
	}
	return nil
}

// CheckIP checks a resolved address against the private-range policy.
func (d *Dialer) CheckIP(ip netip.Addr) error {
	if !d.allowPrivate && IsPrivate(ip) {
		return fmt.Errorf("%w: address %s is private/loopback/link-local/multicast (set allow_private=true to permit)", ErrBlocked, ip)
	}
	return nil
}

// CheckPort enforces the port allowlist for raw sockets.
func (d *Dialer) CheckPort(port int) error {
	if !d.rawSocket || len(d.g.cfg.AllowPorts) == 0 {
		return nil
	}
	for _, p := range d.g.cfg.AllowPorts {
		if p == port {
			return nil
		}
	}
	return fmt.Errorf("%w: port %d is not on the port allow list", ErrBlocked, port)
}

// CheckAddress checks a host:port pair without dialing.
func (d *Dialer) CheckAddress(hostport string) error {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", hostport, err)
	}
	if err := d.CheckHost(host); err != nil {
		return err
	}
	if port, err := strconv.Atoi(portStr); err == nil {
		return d.CheckPort(port)
	}
	return nil
}

// Control is a net.Dialer.Control / net.ListenConfig.Control function that
// rejects connections to blocked IPs. It runs after DNS resolution.
func (d *Dialer) Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrBlocked, address)
	}
	if z := ip.Zone(); z != "" {
		ip = ip.WithZone("")
	}
	return d.CheckIP(ip)
}

// NetDialer returns a *net.Dialer with the IP guard installed. Callers that
// use it directly must call CheckAddress first so hostname lists apply.
func (d *Dialer) NetDialer() *net.Dialer {
	return &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second, Control: d.Control}
}

// DialContext dials with full checks: host lists, port allowlist and IP guard.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.CheckAddress(address); err != nil {
		return nil, err
	}
	return d.NetDialer().DialContext(ctx, network, address)
}

// Dial is DialContext with a background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// ResolveChecked resolves host and returns the first address that passes the
// guard, for protocols (e.g. QUIC) that need a concrete IP before dialing.
func (d *Dialer) ResolveChecked(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if err := d.CheckAddress(hostport); err != nil {
		return netip.AddrPort{}, err
	}
	host, portStr, _ := net.SplitHostPort(hostport)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		p, perr := net.DefaultResolver.LookupPort(ctx, "udp", portStr)
		if perr != nil {
			return netip.AddrPort{}, perr
		}
		port = p
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", strings.Trim(host, "[]"))
	if err != nil {
		return netip.AddrPort{}, err
	}
	var lastErr error
	for _, ip := range ips {
		if err := d.CheckIP(ip); err != nil {
			lastErr = err
			continue
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %s", host)
	}
	return netip.AddrPort{}, lastErr
}

// matchHost matches a host against a glob pattern. "*.example.com" also
// matches "example.com" itself.
func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") && host == pattern[2:] {
		return true
	}
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return prefix.Contains(ip.Unmap())
		}
		return false
	}
	ok, _ := path.Match(pattern, host)
	return ok
}
