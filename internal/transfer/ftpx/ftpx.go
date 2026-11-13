// Package ftpx connects to FTP/FTPS servers with github.com/jlaffaye/ftp,
// routing the control connection and every data connection through a
// caller-supplied guarded dialer. Data connections must go to the control
// host unless TrustPasvIP is set (and are then still checked by the dialer).
package ftpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"

	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/transfer"
)

// TLS modes.
const (
	TLSNone     = "none"
	TLSExplicit = "explicit"
	TLSImplicit = "implicit"
)

// DialFunc dials a TCP connection (normally the SSRF-guarded dialer).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config configures a connection.
type Config struct {
	Host    string
	Port    int
	TLSMode string
	TLS     *tls.Config
	Dial    DialFunc
	// TrustPasvIP uses the address in PASV replies instead of the control
	// host. The data address is still checked by Dial.
	TrustPasvIP bool
	DisableEPSV bool
	DisableMLSD bool
	Timeout     time.Duration
	Idle        time.Duration
	User        string
	Password    string
}

// Conn is a logged-in FTP connection.
type Conn struct {
	*ftp.ServerConn
	cfg       Config
	ctx       context.Context
	closers   *transfer.Closers
	mu        sync.Mutex
	controlIP string
	dataConns int
}

// DataConns returns how many data connections were opened.
func (c *Conn) DataConns() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dataConns
}

// ControlIP is the resolved IP of the control connection.
func (c *Conn) ControlIP() string { return c.controlIP }

// TLSMode returns the TLS mode in use.
func (c *Conn) TLSMode() string { return normMode(c.cfg.TLSMode) }

func normMode(m string) string {
	switch strings.ToLower(m) {
	case "", "none", "false", "off":
		return TLSNone
	case "explicit", "starttls", "auth_tls":
		return TLSExplicit
	case "implicit", "ftps":
		return TLSImplicit
	}
	return m
}

// ValidMode reports whether m is a known TLS mode.
func ValidMode(m string) bool {
	switch normMode(m) {
	case TLSNone, TLSExplicit, TLSImplicit:
		return true
	}
	return false
}

// DefaultPort returns 990 for implicit TLS, else 21.
func DefaultPort(mode string) int {
	if normMode(mode) == TLSImplicit {
		return 990
	}
	return 21
}

// Connect dials, optionally upgrades to TLS, and logs in. Cancelling ctx
// closes every connection.
func Connect(ctx context.Context, cfg Config) (*Conn, error) {
	mode := normMode(cfg.TLSMode)
	if !ValidMode(mode) {
		return nil, fmt.Errorf("unknown tls mode %q (use none, explicit or implicit)", cfg.TLSMode)
	}
	if mode != TLSNone && cfg.TLS == nil {
		return nil, errors.New("TLS mode requires a TLS configuration")
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort(mode)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.User == "" {
		cfg.User, cfg.Password = "anonymous", "anonymous@"
	}
	if cfg.TLS != nil {
		cfg.TLS = cfg.TLS.Clone()
		if cfg.TLS.ClientSessionCache == nil {
			// Many FTPS servers require data connections to resume the
			// control connection's TLS session.
			cfg.TLS.ClientSessionCache = tls.NewLRUClientSessionCache(8)
		}
	}
	c := &Conn{cfg: cfg, ctx: ctx, closers: transfer.CloseOnDone(ctx)}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	opts := []ftp.DialOption{
		ftp.DialWithDialFunc(c.dial),
		ftp.DialWithDisabledEPSV(cfg.DisableEPSV),
		ftp.DialWithTrustPasvIP(cfg.TrustPasvIP),
		ftp.DialWithDisabledMLSD(cfg.DisableMLSD),
		ftp.DialWithShutTimeout(cfg.Timeout),
	}
	switch mode {
	case TLSExplicit:
		opts = append(opts, ftp.DialWithExplicitTLS(cfg.TLS))
	case TLSImplicit:
		opts = append(opts, ftp.DialWithTLS(cfg.TLS))
	}
	sc, err := ftp.Dial(addr, opts...)
	if err != nil {
		c.closers.CloseAll()
		c.closers.Stop()
		return nil, fmt.Errorf("FTP connect to %s: %w", addr, err)
	}
	c.ServerConn = sc
	if err := sc.Login(cfg.User, cfg.Password); err != nil {
		sc.Quit()
		c.closers.CloseAll()
		c.closers.Stop()
		return nil, fmt.Errorf("FTP login as %q failed: %w", cfg.User, err)
	}
	return c, nil
}

// Close sends QUIT and closes all connections.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	if c.ServerConn != nil {
		err = c.ServerConn.Quit()
	}
	c.closers.CloseAll()
	c.closers.Stop()
	return err
}

// dial is used by the ftp library for the control connection (first call)
// and every data connection.
func (c *Conn) dial(network, addr string) (net.Conn, error) {
	c.mu.Lock()
	control := c.controlIP == ""
	controlIP := c.controlIP
	c.mu.Unlock()
	mode := normMode(c.cfg.TLSMode)

	if !control {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if !c.cfg.TrustPasvIP && !sameIP(host, controlIP) {
			return nil, fmt.Errorf("%w: FTP data connection to %s differs from the control host %s (set trust_pasv_ip=true to allow it)", netguard.ErrBlocked, host, controlIP)
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.cfg.Timeout)
	defer cancel()
	raw, err := c.cfg.Dial(ctx, network, addr)
	if err != nil {
		if !control {
			return nil, fmt.Errorf("FTP data connection to %s: %w", addr, err)
		}
		return nil, err
	}
	c.closers.Add(raw)
	if control {
		ta, ok := raw.RemoteAddr().(*net.TCPAddr)
		if !ok {
			raw.Close()
			return nil, errors.New("FTP control connection is not TCP")
		}
		c.mu.Lock()
		c.controlIP = ta.IP.String()
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		c.dataConns++
		c.mu.Unlock()
	}
	conn := transfer.NewIdleConn(raw, c.cfg.Idle)
	switch {
	case mode == TLSImplicit && control:
		tc := tls.Client(conn, c.cfg.TLS)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("implicit TLS handshake: %w", err)
		}
		return tc, nil
	case mode != TLSNone && !control:
		// Handshake happens on first read/write (some servers hang otherwise).
		return tls.Client(conn, c.cfg.TLS), nil
	}
	return conn, nil
}

func sameIP(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return strings.EqualFold(a, b)
	}
	return ia.Equal(ib)
}

// Exists reports whether a remote file exists (via SIZE, then MLST).
func (c *Conn) Exists(p string) (bool, int64) {
	if n, err := c.FileSize(p); err == nil {
		return true, n
	}
	if e, err := c.GetEntry(p); err == nil && e != nil {
		return true, int64(e.Size)
	}
	return false, -1
}

// MkdirAll creates every missing directory of dir (errors for existing
// directories are ignored).
func (c *Conn) MkdirAll(dir string) {
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" || dir == "." || dir == "/" {
		return
	}
	abs := strings.HasPrefix(dir, "/")
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	cur := ""
	if abs {
		cur = "/"
	}
	for _, p := range parts {
		if p == "" {
			continue
		}
		cur = path.Join(cur, p)
		_ = c.MakeDir(cur)
	}
}

// Entry is one listed remote file.
type Entry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Size    uint64 `json:"size"`
	ModTime string `json:"mtime,omitempty"`
	IsDir   bool   `json:"is_dir"`
	Target  string `json:"symlink_target,omitempty"`
	Depth   int    `json:"depth"`
}

// ListOptions bound a listing.
type ListOptions struct {
	Recursive  bool
	MaxDepth   int
	MaxEntries int
}

// ListResult is a bounded listing.
type ListResult struct {
	Entries   []Entry
	Truncated bool
	Command   string
}

// List lists dir (recursively within the bounds of o).
func (c *Conn) List(ctx context.Context, dir string, o ListOptions) (*ListResult, error) {
	res := &ListResult{}
	maxDepth := 1
	if o.Recursive {
		maxDepth = o.MaxDepth
	}
	var walk func(d string, depth int) error
	walk = func(d string, depth int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entries, err := c.listOne(d, res)
		if err != nil {
			if depth == 1 {
				return err
			}
			return nil
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			if len(res.Entries) >= o.MaxEntries {
				res.Truncated = true
				return nil
			}
			p := path.Join(d, e.Name)
			if d == "" {
				p = e.Name
			}
			out := Entry{Name: e.Name, Path: p, Type: e.Type.String(), Size: e.Size, IsDir: e.Type == ftp.EntryTypeFolder, Target: e.Target, Depth: depth}
			if !e.Time.IsZero() {
				out.ModTime = e.Time.UTC().Format(time.RFC3339)
			}
			res.Entries = append(res.Entries, out)
			if out.IsDir && depth < maxDepth {
				if err := walk(p, depth+1); err != nil {
					return err
				}
				if res.Truncated {
					return nil
				}
			}
		}
		return nil
	}
	if err := walk(dir, 1); err != nil {
		return nil, err
	}
	return res, nil
}

// ErrMLSDFailed is returned by List when the server advertised MLST but
// MLSD failed; reconnect with Config.DisableMLSD to fall back to LIST.
var ErrMLSDFailed = errors.New("MLSD listing failed")

func (c *Conn) listOne(dir string, res *ListResult) ([]*ftp.Entry, error) {
	usedMLSD := c.IsTimePreciseInList()
	entries, err := c.ServerConn.List(dir)
	if err != nil {
		if usedMLSD {
			return nil, fmt.Errorf("%w for %q: %v", ErrMLSDFailed, dir, err)
		}
		return nil, fmt.Errorf("LIST %q: %w", dir, err)
	}
	if usedMLSD {
		res.Command = "MLSD"
	} else {
		res.Command = "LIST"
	}
	return entries, nil
}

// Config returns the connection's configuration (for reconnecting).
func (c *Conn) Config() Config { return c.cfg }
