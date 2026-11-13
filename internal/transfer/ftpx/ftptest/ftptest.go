// Package ftptest is a minimal protocol-level FTP/FTPS server for tests. It
// implements the commands github.com/jlaffaye/ftp uses (USER, PASS, FEAT,
// TYPE, OPTS, AUTH TLS, PBSZ, PROT, PWD, CWD, EPSV, PASV, LIST, MLSD, MLST,
// NLST, SIZE, REST, RETR, STOR, MKD, DELE, NOOP, QUIT) over a directory on
// 127.0.0.1. It is not a real FTP server: one data connection at a time,
// passive mode only.
package ftptest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Options configure the server.
type Options struct {
	// User and Password are the accepted login (empty User: accept any).
	User     string
	Password string
	// TLS enables AUTH TLS (explicit FTPS) and PROT P.
	TLS *tls.Config
	// Implicit wraps the control connection in TLS from the first byte.
	Implicit bool
	// RequireTLS refuses USER before AUTH TLS.
	RequireTLS bool
	// MLSD advertises MLST in FEAT (so clients list with MLSD).
	MLSD bool
	// FailMLSD makes MLSD fail with 500 (clients should fall back to LIST).
	FailMLSD bool
	// NoEPSV rejects EPSV (clients fall back to PASV).
	NoEPSV bool
	// PasvIP is the address announced in PASV replies (default 127.0.0.1).
	// The data listener is always on 127.0.0.1.
	PasvIP string
	// MaxSessions, when > 0, makes every control connection after the
	// first MaxSessions get "421 Too many connections".
	MaxSessions int
}

// Server is a running fake FTP server.
type Server struct {
	Addr string
	Port int
	Root string

	opts     Options
	ln       net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    []net.Conn
	cmds     []string
	data     int
	sessions int
}

// New starts a server on 127.0.0.1:0 serving root; it stops on t.Cleanup.
func New(t testing.TB, root string, o Options) *Server {
	t.Helper()
	if o.PasvIP == "" {
		o.PasvIP = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String(), Port: ln.Addr().(*net.TCPAddr).Port, Root: root, opts: o, ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.track(c)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(c)
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
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

// Commands returns the commands received so far ("PASS ***" masked).
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

// HasCommand reports whether a command starting with prefix was received.
func (s *Server) HasCommand(prefix string) bool {
	for _, c := range s.Commands() {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// DataConns is the number of data connections accepted.
func (s *Server) DataConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

type session struct {
	s      *Server
	raw    net.Conn
	conn   net.Conn
	r      *bufio.Reader
	user   string
	authed bool
	secure bool
	prot   bool
	cwd    string
	rest   int64
	pasv   net.Listener
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	s.sessions++
	n := s.sessions
	s.mu.Unlock()
	if s.opts.MaxSessions > 0 && n > s.opts.MaxSessions {
		io.WriteString(c, "421 Too many connections\r\n")
		return
	}
	ss := &session{s: s, raw: c, conn: c, cwd: "/"}
	if s.opts.Implicit {
		ss.conn = tls.Server(c, s.opts.TLS)
		ss.secure, ss.prot = true, true
	}
	ss.r = bufio.NewReader(ss.conn)
	defer func() {
		if ss.pasv != nil {
			ss.pasv.Close()
		}
	}()
	ss.reply(220, "netkit fake FTP ready")
	for {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		rec := line
		if cmd == "PASS" {
			rec = "PASS ***"
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, rec)
		s.mu.Unlock()
		if !ss.handle(cmd, arg) {
			return
		}
	}
}

func (ss *session) reply(code int, msg string) {
	fmt.Fprintf(ss.conn, "%d %s\r\n", code, msg)
}

func (ss *session) replyLines(code int, first string, lines []string, last string) {
	var b strings.Builder
	fmt.Fprintf(&b, "%d-%s\r\n", code, first)
	for _, l := range lines {
		b.WriteString(" " + l + "\r\n")
	}
	fmt.Fprintf(&b, "%d %s\r\n", code, last)
	io.WriteString(ss.conn, b.String())
}

// resolve maps an FTP path to a local path inside the root.
func (ss *session) resolve(arg string) (remote, local string) {
	p := arg
	if !path.IsAbs(p) {
		p = path.Join(ss.cwd, p)
	}
	p = path.Clean("/" + p)
	return p, filepath.Join(ss.s.Root, filepath.FromSlash(p))
}

func (ss *session) handle(cmd, arg string) bool {
	o := ss.s.opts
	if !ss.authed {
		switch cmd {
		case "USER", "PASS", "AUTH", "FEAT", "QUIT", "SYST", "NOOP", "PBSZ", "PROT", "OPTS":
		default:
			ss.reply(530, "Please login with USER and PASS")
			return true
		}
	}
	switch cmd {
	case "AUTH":
		if o.TLS == nil || !strings.EqualFold(arg, "TLS") || ss.secure {
			ss.reply(502, "AUTH not supported")
			return true
		}
		ss.reply(234, "AUTH TLS OK")
		tc := tls.Server(ss.raw, o.TLS)
		if err := tc.Handshake(); err != nil {
			return false
		}
		ss.conn, ss.secure = tc, true
		ss.r = bufio.NewReader(tc)
	case "USER":
		if o.RequireTLS && !ss.secure {
			ss.reply(530, "TLS required (use AUTH TLS)")
			return true
		}
		ss.user = arg
		ss.reply(331, "Password required")
	case "PASS":
		if o.User == "" || (ss.user == o.User && arg == o.Password) {
			ss.authed = true
			ss.reply(230, "Logged in")
		} else {
			ss.reply(530, "Login incorrect")
		}
	case "FEAT":
		feats := []string{"SIZE", "REST STREAM", "UTF8"}
		if !o.NoEPSV {
			feats = append(feats, "EPSV")
		}
		if o.MLSD {
			feats = append(feats, "MLST type*;size*;modify*;")
		}
		if o.TLS != nil {
			feats = append(feats, "AUTH TLS", "PBSZ", "PROT")
		}
		ss.replyLines(211, "Features:", feats, "End")
	case "SYST":
		ss.reply(215, "UNIX Type: L8")
	case "TYPE", "OPTS", "NOOP", "MODE", "STRU":
		ss.reply(200, "OK")
	case "PBSZ":
		ss.reply(200, "PBSZ=0")
	case "PROT":
		switch strings.ToUpper(arg) {
		case "P":
			if !ss.secure {
				ss.reply(503, "PROT P requires TLS")
				return true
			}
			ss.prot = true
		case "C":
			ss.prot = false
		default:
			ss.reply(504, "unsupported protection level")
			return true
		}
		ss.reply(200, "PROT OK")
	case "PWD":
		ss.reply(257, strconv.Quote(ss.cwd)+" is the current directory")
	case "CWD":
		rp, lp := ss.resolve(arg)
		if st, err := os.Stat(lp); err != nil || !st.IsDir() {
			ss.reply(550, "No such directory")
			return true
		}
		ss.cwd = rp
		ss.reply(250, "OK")
	case "EPSV":
		if o.NoEPSV {
			ss.reply(502, "EPSV not supported")
			return true
		}
		port, err := ss.listen()
		if err != nil {
			ss.reply(425, err.Error())
			return true
		}
		ss.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
	case "PASV":
		port, err := ss.listen()
		if err != nil {
			ss.reply(425, err.Error())
			return true
		}
		ip := strings.ReplaceAll(o.PasvIP, ".", ",")
		ss.reply(227, fmt.Sprintf("Entering Passive Mode (%s,%d,%d).", ip, port/256, port%256))
	case "REST":
		n, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || n < 0 {
			ss.reply(501, "bad offset")
			return true
		}
		ss.rest = n
		ss.reply(350, "Restarting at "+arg)
	case "SIZE":
		_, lp := ss.resolve(arg)
		st, err := os.Stat(lp)
		if err != nil || st.IsDir() {
			ss.reply(550, "No such file")
			return true
		}
		ss.reply(213, strconv.FormatInt(st.Size(), 10))
	case "MLST":
		if !o.MLSD {
			ss.reply(502, "MLST not supported")
			return true
		}
		rp, lp := ss.resolve(arg)
		st, err := os.Stat(lp)
		if err != nil {
			ss.reply(550, "No such file")
			return true
		}
		ss.replyLines(250, "Listing "+rp, []string{mlsdFacts(st) + " " + rp}, "End")
	case "MKD":
		rp, lp := ss.resolve(arg)
		if err := os.Mkdir(lp, 0o755); err != nil {
			ss.reply(550, "Cannot create directory")
			return true
		}
		ss.reply(257, strconv.Quote(rp)+" created")
	case "DELE":
		_, lp := ss.resolve(arg)
		if err := os.Remove(lp); err != nil {
			ss.reply(550, "Cannot delete")
			return true
		}
		ss.reply(250, "Deleted")
	case "LIST", "NLST", "MLSD":
		ss.list(cmd, arg)
	case "RETR":
		ss.retr(arg)
	case "STOR":
		ss.stor(arg)
	case "QUIT":
		ss.reply(221, "Bye")
		return false
	default:
		ss.reply(502, "Command not implemented")
	}
	return true
}

func (ss *session) listen() (int, error) {
	if ss.pasv != nil {
		ss.pasv.Close()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	ss.pasv = ln
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// dataConn accepts the pending passive data connection.
func (ss *session) dataConn() (net.Conn, error) {
	ln := ss.pasv
	ss.pasv = nil
	if ln == nil {
		return nil, fmt.Errorf("use PASV or EPSV first")
	}
	defer ln.Close()
	if tl, ok := ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(10 * time.Second))
	}
	c, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	ss.s.track(c)
	ss.s.mu.Lock()
	ss.s.data++
	ss.s.mu.Unlock()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	return c, nil
}

func (ss *session) abortData() {
	if ss.pasv != nil {
		ss.pasv.Close()
		ss.pasv = nil
	}
	ss.rest = 0
}

func (ss *session) transfer(fn func(c net.Conn) error) {
	c, err := ss.dataConn()
	if err != nil {
		ss.reply(425, "Cannot open data connection: "+err.Error())
		return
	}
	ss.reply(150, "Opening data connection")
	if ss.prot {
		// Like real servers: accept TLS right after 150, even when no
		// data follows.
		tc := tls.Server(c, ss.s.opts.TLS)
		if err := tc.Handshake(); err != nil {
			c.Close()
			ss.reply(425, "TLS handshake on the data connection failed: "+err.Error())
			return
		}
		c = tc
	}
	err = fn(c)
	cerr := c.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		ss.reply(426, "Transfer aborted: "+err.Error())
		return
	}
	ss.reply(226, "Transfer complete")
}

func mlsdFacts(st os.FileInfo) string {
	mod := st.ModTime().UTC().Format("20060102150405")
	if st.IsDir() {
		return "type=dir;modify=" + mod + ";"
	}
	return fmt.Sprintf("type=file;size=%d;modify=%s;", st.Size(), mod)
}

func (ss *session) list(cmd, arg string) {
	o := ss.s.opts
	if cmd == "MLSD" && (!o.MLSD || o.FailMLSD) {
		ss.abortData()
		ss.reply(500, "MLSD not understood")
		return
	}
	// Strip ls-style flags ("LIST -a dir").
	for strings.HasPrefix(arg, "-") {
		_, arg, _ = strings.Cut(arg, " ")
	}
	_, lp := ss.resolve(arg)
	st, err := os.Stat(lp)
	if err != nil {
		ss.abortData()
		ss.reply(550, "No such file or directory")
		return
	}
	var infos []os.FileInfo
	if st.IsDir() {
		des, err := os.ReadDir(lp)
		if err != nil {
			ss.abortData()
			ss.reply(550, "Cannot read directory")
			return
		}
		for _, de := range des {
			if fi, err := de.Info(); err == nil {
				infos = append(infos, fi)
			}
		}
	} else {
		infos = []os.FileInfo{st}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
	var b strings.Builder
	for _, fi := range infos {
		switch cmd {
		case "MLSD":
			b.WriteString(mlsdFacts(fi) + " " + fi.Name() + "\r\n")
		case "NLST":
			b.WriteString(fi.Name() + "\r\n")
		default:
			perm := "-rw-r--r--"
			if fi.IsDir() {
				perm = "drwxr-xr-x"
			}
			fmt.Fprintf(&b, "%s 1 owner group %d %s %s\r\n", perm, fi.Size(), fi.ModTime().UTC().Format("Jan _2  2006"), fi.Name())
		}
	}
	ss.transfer(func(c net.Conn) error {
		_, err := io.WriteString(c, b.String())
		return err
	})
}

func (ss *session) retr(arg string) {
	_, lp := ss.resolve(arg)
	f, err := os.Open(lp)
	if err != nil {
		ss.abortData()
		ss.reply(550, "No such file")
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.IsDir() {
		ss.abortData()
		ss.reply(550, "Not a file")
		return
	}
	off := ss.rest
	ss.rest = 0
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			ss.abortData()
			ss.reply(550, "Cannot seek")
			return
		}
	}
	ss.transfer(func(c net.Conn) error {
		_, err := io.Copy(c, f)
		return err
	})
}

func (ss *session) stor(arg string) {
	_, lp := ss.resolve(arg)
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	off := ss.rest
	ss.rest = 0
	if off > 0 {
		flags = os.O_WRONLY | os.O_CREATE
	}
	f, err := os.OpenFile(lp, flags, 0o644)
	if err != nil {
		ss.abortData()
		ss.reply(553, "Cannot create file")
		return
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			ss.abortData()
			ss.reply(553, "Cannot seek")
			return
		}
	}
	ss.transfer(func(c net.Conn) error {
		_, err := io.Copy(f, c)
		return err
	})
}

// SelfSigned returns a server TLS config with a self-signed certificate
// for 127.0.0.1 / localhost, and the certificate in PEM form (to pass as a
// client CA).
func SelfSigned(t testing.TB) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "netkit ftptest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, string(certPEM)
}
