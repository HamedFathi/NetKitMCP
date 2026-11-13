// Package sftptest runs an in-process SSH server with the pkg/sftp
// subsystem, serving a directory on 127.0.0.1, for tests.
package sftptest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Options configure the server.
type Options struct {
	// Root is the directory served (relative SFTP paths resolve inside it).
	Root string
	// User and Password enable password (and keyboard-interactive) auth.
	User     string
	Password string
	// AuthorizedKey enables public-key auth for User.
	AuthorizedKey ssh.PublicKey
	// HostKey is the server's host key (nil: a fresh ed25519 key).
	HostKey ssh.Signer
}

// Server is a running SSH/SFTP server.
type Server struct {
	Addr    string
	Port    int
	HostKey ssh.Signer

	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  []net.Conn
	logins []string
}

// NewKey returns a fresh ed25519 signer and its private key in OpenSSH PEM
// form (encrypted when passphrase is not empty).
func NewKey(t testing.TB, passphrase string) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var blk *pem.Block
	if passphrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	return s, pem.EncodeToMemory(blk)
}

// New starts a server; it is stopped by t.Cleanup.
func New(t testing.TB, o Options) *Server {
	t.Helper()
	if o.HostKey == nil {
		o.HostKey, _ = NewKey(t, "")
	}
	cfg := &ssh.ServerConfig{}
	if o.Password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == o.User && string(pw) == o.Password {
				return nil, nil
			}
			return nil, errors.New("bad password")
		}
	}
	if o.AuthorizedKey != nil {
		want := o.AuthorizedKey.Marshal()
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == o.User && string(k.Marshal()) == string(want) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		}
	}
	cfg.AddHostKey(o.HostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ln: ln, HostKey: o.HostKey, Addr: ln.Addr().String(), Port: ln.Addr().(*net.TCPAddr).Port}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handle(c, cfg, o.Root)
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

// Close stops the server and drops every connection.
func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// PortString is the port as a string.
func (s *Server) PortString() string { return strconv.Itoa(s.Port) }

// Logins returns the users that authenticated, with the method used
// ("user/password" or "user/publickey").
func (s *Server) Logins() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.logins...)
}

// KnownHostsLine is a known_hosts line for this server's host key.
func (s *Server) KnownHostsLine() string {
	return knownhosts.Line([]string{knownhosts.Normalize(s.Addr)}, s.HostKey.PublicKey())
}

// Fingerprint is the SHA256 fingerprint of the host key.
func (s *Server) Fingerprint() string { return ssh.FingerprintSHA256(s.HostKey.PublicKey()) }

func (s *Server) handle(c net.Conn, cfg *ssh.ServerConfig, root string) {
	defer c.Close()
	// Record the auth method that succeeded.
	conf := *cfg
	var method string
	if cfg.PasswordCallback != nil {
		conf.PasswordCallback = func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			p, err := cfg.PasswordCallback(m, pw)
			if err == nil {
				method = "password"
			}
			return p, err
		}
	}
	if cfg.PublicKeyCallback != nil {
		conf.PublicKeyCallback = func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			p, err := cfg.PublicKeyCallback(m, k)
			if err == nil {
				method = "publickey"
			}
			return p, err
		}
	}
	sc, chans, reqs, err := ssh.NewServerConn(c, &conf)
	if err != nil {
		return
	}
	defer sc.Close()
	s.mu.Lock()
	s.logins = append(s.logins, sc.User()+"/"+method)
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				ok := r.Type == "subsystem" && len(r.Payload) >= 4 && string(r.Payload[4:]) == "sftp"
				r.Reply(ok, nil)
				if !ok {
					continue
				}
				srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(root))
				if err != nil {
					return
				}
				srv.Serve()
				srv.Close()
				return
			}
		}()
	}
}
