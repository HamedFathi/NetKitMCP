// Package sftpx connects to SFTP servers over SSH with mandatory host-key
// verification (known_hosts or a pinned fingerprint, or an explicit
// insecure opt-out), password / keyboard-interactive / public-key auth, and
// a caller-supplied guarded dialer.
package sftpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/HamedFathi/NetKitMCP/internal/transfer"
)

// Credentials are the SSH login credentials.
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte
	Passphrase string
}

// Signer parses the private key (if any).
func (c Credentials) Signer() (ssh.Signer, error) {
	if len(c.PrivateKey) == 0 {
		return nil, nil
	}
	var s ssh.Signer
	var err error
	if c.Passphrase != "" {
		s, err = ssh.ParsePrivateKeyWithPassphrase(c.PrivateKey, []byte(c.Passphrase))
	} else {
		s, err = ssh.ParsePrivateKey(c.PrivateKey)
	}
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, errors.New("the private key is encrypted: set auth.ssh.passphrase")
		}
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return s, nil
}

// AuthMethods returns the SSH auth methods for the credentials.
func (c Credentials) AuthMethods() ([]ssh.AuthMethod, error) {
	var m []ssh.AuthMethod
	s, err := c.Signer()
	if err != nil {
		return nil, err
	}
	if s != nil {
		m = append(m, ssh.PublicKeys(s))
	}
	if c.Password != "" {
		pw := c.Password
		m = append(m, ssh.Password(pw))
		m = append(m, ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = pw
			}
			return answers, nil
		}))
	}
	if len(m) == 0 {
		return nil, errors.New("no SSH credentials: use auth.type=ssh_password with auth.password, or auth.type=ssh_key with auth.ssh.private_key")
	}
	return m, nil
}

// DialFunc dials a TCP connection (normally the SSRF-guarded dialer).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config configures a connection.
type Config struct {
	Addr        string // host:port
	Credentials Credentials
	HostKey     HostKeyPolicy
	Dial        DialFunc
	// Timeout bounds the TCP connect and SSH handshake.
	Timeout time.Duration
	// Idle bounds inactivity on the connection once established.
	Idle time.Duration
	// Concurrency is the number of outstanding SFTP requests per file.
	Concurrency int
}

// Client is a connected SFTP client.
type Client struct {
	*sftp.Client
	SSH           *ssh.Client
	HostKey       HostKeyInfo
	ServerVersion string
	closers       *transfer.Closers
}

// Close closes the SFTP session and the SSH connection.
func (c *Client) Close() error {
	c.Client.Close()
	err := c.SSH.Close()
	c.closers.Stop()
	return err
}

// Connect dials, verifies the host key, authenticates and starts SFTP.
// Cancelling ctx closes the connection.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Credentials.Username == "" {
		return nil, errors.New("auth.username is required for SFTP")
	}
	v, err := NewVerifier(cfg.HostKey)
	if err != nil {
		return nil, err
	}
	methods, err := cfg.Credentials.AuthMethods()
	if err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	sc := &ssh.ClientConfig{
		User:            cfg.Credentials.Username,
		Auth:            methods,
		HostKeyCallback: v.Callback(),
		Timeout:         cfg.Timeout,
	}
	if len(cfg.HostKey.KnownHosts) > 0 && cfg.HostKey.Fingerprint == "" {
		sc.HostKeyAlgorithms = HostKeyAlgorithms(cfg.HostKey.KnownHosts, cfg.Addr)
	}
	closers := transfer.CloseOnDone(ctx)
	dctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	raw, err := cfg.Dial(dctx, "tcp", cfg.Addr)
	cancel()
	if err != nil {
		closers.Stop()
		return nil, err
	}
	closers.Add(raw)
	_ = raw.SetDeadline(time.Now().Add(cfg.Timeout))
	conn := transfer.NewIdleConn(raw, cfg.Idle)
	sconn, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr, sc)
	if err != nil {
		raw.Close()
		closers.Stop()
		if errors.Is(err, ErrHostKey) || strings.Contains(err.Error(), ErrHostKey.Error()) {
			return nil, unwrapHostKeyErr(err)
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("SSH authentication failed for user %q: %w", cfg.Credentials.Username, err)
		}
		return nil, fmt.Errorf("SSH handshake with %s: %w", cfg.Addr, err)
	}
	if cfg.Idle <= 0 {
		_ = raw.SetDeadline(time.Time{})
	}
	client := ssh.NewClient(sconn, chans, reqs)
	opts := []sftp.ClientOption{sftp.UseConcurrentWrites(true), sftp.UseConcurrentReads(true)}
	if cfg.Concurrency > 0 {
		opts = append(opts, sftp.MaxConcurrentRequestsPerFile(cfg.Concurrency))
	}
	sf, err := sftp.NewClient(client, opts...)
	if err != nil {
		client.Close()
		closers.Stop()
		return nil, fmt.Errorf("starting the SFTP subsystem: %w", err)
	}
	out := &Client{Client: sf, SSH: client, closers: closers, ServerVersion: string(sconn.ServerVersion())}
	if v.Observed != nil {
		out.HostKey = *v.Observed
	}
	return out, nil
}

// unwrapHostKeyErr strips the "ssh: handshake failed:" prefix.
func unwrapHostKeyErr(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, ErrHostKey.Error()); i > 0 {
		return fmt.Errorf("%w%s", ErrHostKey, msg[i+len(ErrHostKey.Error()):])
	}
	return err
}

// Entry is one listed remote file.
type Entry struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	Mode          string `json:"mode"`
	Perm          string `json:"perm"`
	ModTime       string `json:"mtime"`
	IsDir         bool   `json:"is_dir"`
	IsSymlink     bool   `json:"is_symlink,omitempty"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
	Depth         int    `json:"depth"`
}

// ListOptions bound a listing.
type ListOptions struct {
	Recursive  bool
	MaxDepth   int
	MaxEntries int
}

// List lists p (a directory, or a single file). It returns truncated=true
// when MaxEntries was hit.
func (c *Client) List(ctx context.Context, p string, o ListOptions) ([]Entry, bool, error) {
	if p == "" {
		p = "."
	}
	st, err := c.Lstat(p)
	if err != nil {
		return nil, false, fmt.Errorf("stat %s: %w", p, err)
	}
	if !st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
		return []Entry{c.entry(p, st, 0)}, false, nil
	}
	if st.Mode()&os.ModeSymlink != 0 {
		if t, err := c.Stat(p); err != nil || !t.IsDir() {
			return []Entry{c.entry(p, st, 0)}, false, nil
		}
	}
	maxDepth := 1
	if o.Recursive {
		maxDepth = o.MaxDepth
	}
	var out []Entry
	truncated := false
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		infos, err := c.ReadDir(dir)
		if err != nil {
			if depth == 1 {
				return fmt.Errorf("list %s: %w", dir, err)
			}
			return nil // unreadable subdirectory: skip
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		for _, fi := range infos {
			if fi.Name() == "." || fi.Name() == ".." {
				continue
			}
			if len(out) >= o.MaxEntries {
				truncated = true
				return nil
			}
			fp := path.Join(dir, fi.Name())
			out = append(out, c.entry(fp, fi, depth))
			if fi.IsDir() && depth < maxDepth {
				if err := walk(fp, depth+1); err != nil {
					return err
				}
				if truncated {
					return nil
				}
			}
		}
		return nil
	}
	if err := walk(p, 1); err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

func (c *Client) entry(p string, fi os.FileInfo, depth int) Entry {
	e := Entry{
		Name:    fi.Name(),
		Path:    p,
		Size:    fi.Size(),
		Mode:    fi.Mode().String(),
		Perm:    fmt.Sprintf("%04o", fi.Mode().Perm()),
		ModTime: fi.ModTime().UTC().Format(time.RFC3339),
		IsDir:   fi.IsDir(),
		Depth:   depth,
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		e.IsSymlink = true
		if t, err := c.ReadLink(p); err == nil {
			e.SymlinkTarget = t
		}
	}
	return e
}
