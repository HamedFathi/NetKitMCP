// Command netkit-mcp is an MCP server that speaks API, messaging and
// file-transfer protocols. It is pure Go and never shells out.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/all"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netkit-mcp:", err)
		os.Exit(1)
	}
}

// options is the parsed command line.
type options struct {
	cfg       *config.Config
	groups    map[string]bool
	transport string
	addr      string
	httpPath  string
	token     string
	logger    *slog.Logger
	version   bool
}

// parseOptions parses flags (args excludes the program name), with
// defaults taken from NETKIT_* environment variables read through getenv.
func parseOptions(args []string, getenv func(string) string, stderr io.Writer) (*options, error) {
	envOr := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	envList := func(name string) listFlag {
		var l listFlag
		if v := getenv(name); v != "" {
			l.Set(v)
		}
		return l
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("netkit-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		readDirs   = envList("NETKIT_ALLOW_READ_DIR")
		writeDirs  = envList("NETKIT_ALLOW_WRITE_DIR")
		allowHosts = envList("NETKIT_ALLOW_HOSTS")
		denyHosts  = envList("NETKIT_DENY_HOSTS")
		allowPorts = envList("NETKIT_ALLOW_PORTS")
	)
	groups := fs.String("groups", getenv("NETKIT_GROUPS"), "comma-separated tool groups: "+strings.Join(tools.AllGroups, ",")+", all, default (default: "+strings.Join(tools.DefaultGroups, ",")+")")
	transport := fs.String("transport", envOr("NETKIT_TRANSPORT", "stdio"), "stdio or http")
	addr := fs.String("addr", envOr("NETKIT_ADDR", "127.0.0.1:8080"), "listen address for --transport http")
	httpPath := fs.String("path", envOr("NETKIT_HTTP_PATH", "/mcp"), "endpoint path for --transport http")
	bearer := fs.String("http-token", getenv("NETKIT_HTTP_TOKEN"), "bearer token required by --transport http (strongly recommended)")
	private := fs.String("private-networks", envOr("NETKIT_PRIVATE_NETWORKS", string(config.PrivateOptIn)), "deny, optin (honor per-call allow_private) or allow")
	maxSessions := fs.Int("max-sessions", cfg.MaxSessions, "maximum interactive sessions")
	sessionTTL := fs.Duration("session-idle-ttl", cfg.SessionIdleTTL, "idle timeout for interactive sessions")
	maxResp := fs.Int64("max-response-bytes", cfg.MaxResponseBytes, "hard ceiling for inline response bodies")
	maxUp := fs.Int64("max-upload-bytes", cfg.MaxUploadBytes, "hard ceiling for uploads")
	maxDown := fs.Int64("max-download-bytes", cfg.MaxDownloadBytes, "hard ceiling for downloads")
	maxTimeout := fs.Duration("max-timeout", cfg.MaxTimeout, "hard ceiling for per-call timeouts")
	logLevel := fs.String("log-level", envOr("NETKIT_LOG_LEVEL", "warn"), "debug, info, warn, error (logs go to stderr)")
	version := fs.Bool("version", false, "print version and exit")
	fs.Var(&readDirs, "allow-read-dir", "existing directory files may be read from; a leading ~ is expanded (repeatable)")
	fs.Var(&writeDirs, "allow-write-dir", "existing directory files may be written to, also readable; a leading ~ is expanded (repeatable)")
	fs.Var(&allowHosts, "allow-hosts", "host allow list, glob or CIDR (repeatable; empty = all)")
	fs.Var(&denyHosts, "deny-hosts", "host deny list, glob or CIDR (repeatable)")
	fs.Var(&allowPorts, "allow-ports", "port allow list for raw tcp/udp/dns tools (repeatable; empty = all)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	o := &options{cfg: cfg, transport: *transport, addr: *addr, httpPath: *httpPath, token: *bearer, version: *version}
	if o.version {
		return o, nil
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return nil, fmt.Errorf("invalid --log-level: %w", err)
	}
	o.logger = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))

	cfg.AllowReadDirs = readDirs
	cfg.AllowWriteDirs = writeDirs
	cfg.AllowHosts = allowHosts
	cfg.DenyHosts = denyHosts
	for _, p := range allowPorts {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q in --allow-ports", p)
		}
		cfg.AllowPorts = append(cfg.AllowPorts, n)
	}
	switch config.PrivateMode(*private) {
	case config.PrivateDeny, config.PrivateOptIn, config.PrivateAllow:
		cfg.PrivateMode = config.PrivateMode(*private)
	default:
		return nil, fmt.Errorf("invalid --private-networks %q", *private)
	}
	cfg.MaxSessions = *maxSessions
	cfg.SessionIdleTTL = *sessionTTL
	cfg.MaxResponseBytes = *maxResp
	cfg.MaxUploadBytes = *maxUp
	cfg.MaxDownloadBytes = *maxDown
	cfg.MaxTimeout = *maxTimeout
	clampDefaults(cfg)

	switch o.transport {
	case "stdio", "http":
	default:
		return nil, fmt.Errorf("invalid --transport %q (stdio or http)", o.transport)
	}
	if o.transport == "http" && !strings.HasPrefix(o.httpPath, "/") {
		return nil, fmt.Errorf("invalid --path %q: must start with /", o.httpPath)
	}

	enabled, err := tools.ParseGroups(*groups)
	if err != nil {
		return nil, err
	}
	o.groups = enabled
	return o, nil
}

// newServer builds the MCP server with the enabled tool groups.
func newServer(deps *tools.Deps, enabled map[string]bool, logger *slog.Logger) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netkit-mcp", Title: "NetKit MCP", Version: config.Version}, &mcp.ServerOptions{
		Instructions: "netkit-mcp speaks HTTP, GraphQL, gRPC, WebSocket, Socket.IO, SOAP, messaging, file-transfer and low-level network protocols. " +
			"Prefer one-shot tools; use session tools (handles) only for interactive exchanges. " +
			"Files are streamed from/to allowed directories only; call netkit_info to see them.",
		Logger: logger,
	})
	tools.Register(s, deps, enabled)
	return s
}

// httpHandler serves the stateless streamable HTTP transport at path,
// protected by the bearer token when one is set, plus /healthz.
func httpHandler(srv *mcp.Server, path, token string, logger *slog.Logger) http.Handler {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true,
		Logger:    logger,
	})
	mux := http.NewServeMux()
	mux.Handle(path, requireBearer(token, http.NewCrossOriginProtection().Handler(h)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// run parses args and serves until ctx is cancelled (or stdin closes for
// the stdio transport).
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	o, err := parseOptions(args, getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if o.version {
		fmt.Fprintln(stdout, "netkit-mcp", config.Version)
		return nil
	}
	logger := o.logger
	deps, err := tools.NewDeps(o.cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	deps.Sessions.Start(ctx)
	defer deps.Sessions.CloseAll()

	if o.transport == "stdio" {
		logger.Info("serving MCP over stdio")
		err := newServer(deps, o.groups, logger).Run(ctx, &mcp.StdioTransport{})
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}

	if o.token == "" {
		logger.Warn("--transport http without --http-token: anyone who can reach the port can use this server")
	}
	hs := &http.Server{
		Addr:              o.addr,
		Handler:           httpHandler(newServer(deps, o.groups, logger), o.httpPath, o.token, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	logger.Info("serving MCP over streamable HTTP", "addr", o.addr, "path", o.httpPath)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func clampDefaults(c *config.Config) {
	if c.DefaultResponseBytes > c.MaxResponseBytes {
		c.DefaultResponseBytes = c.MaxResponseBytes
	}
	if c.DefaultUploadBytes > c.MaxUploadBytes {
		c.DefaultUploadBytes = c.MaxUploadBytes
	}
	if c.DefaultDownloadBytes > c.MaxDownloadBytes {
		c.DefaultDownloadBytes = c.MaxDownloadBytes
	}
	if c.DefaultTimeout > c.MaxTimeout {
		c.DefaultTimeout = c.MaxTimeout
	}
}

func requireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The auth scheme is case-insensitive (RFC 9110 §11.1).
		scheme, got, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netkit-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
