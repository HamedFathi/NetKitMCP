// Package tools holds the MCP tool handlers. Handlers stay thin: validate,
// resolve files through fileio, build clients through the shared factories,
// call a protocol package, and shape the result.
//
// Each tool family registers itself from its own file with RegisterGroup in
// an init function, so families can be developed independently.
package tools

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// Deps are the shared services every handler may use.
type Deps struct {
	Cfg      *config.Config
	Guard    *netguard.Guard
	Files    *fileio.Policy
	HTTP     *httpx.Factory
	Auth     *auth.Manager
	Sessions *session.Registry
}

// NewDeps wires the shared services from a configuration.
func NewDeps(cfg *config.Config) (*Deps, error) {
	files, err := fileio.NewPolicy(cfg.AllowReadDirs, cfg.AllowWriteDirs)
	if err != nil {
		return nil, err
	}
	g := netguard.New(cfg)
	am := auth.NewManager()
	return &Deps{
		Cfg:      cfg,
		Guard:    g,
		Files:    files,
		Auth:     am,
		HTTP:     &httpx.Factory{Cfg: cfg, Guard: g, Files: files, Auth: am},
		Sessions: session.New(cfg.MaxSessions, cfg.SessionIdleTTL),
	}, nil
}

// AuthEnv returns the auth environment for a call.
func (d *Deps) AuthEnv(allowPrivate bool) auth.Env { return d.HTTP.AuthEnv(allowPrivate) }

// Group names.
const (
	GroupHTTP      = "http"
	GroupGRPC      = "grpc"
	GroupWS        = "ws"
	GroupSOAP      = "soap"
	GroupMQTT      = "mqtt"
	GroupMessaging = "messaging"
	GroupTransfer  = "transfer"
	GroupLowLevel  = "lowlevel"
	GroupMCP       = "mcp"
	GroupAuth      = "auth"
)

// AllGroups lists every group in display order.
var AllGroups = []string{GroupHTTP, GroupGRPC, GroupWS, GroupSOAP, GroupMQTT, GroupMessaging, GroupTransfer, GroupLowLevel, GroupMCP, GroupAuth}

// DefaultGroups are enabled when --groups is not given.
var DefaultGroups = []string{GroupHTTP, GroupGRPC, GroupWS, GroupSOAP, GroupAuth, GroupMQTT}

type registrar struct {
	group string
	fn    func(s *mcp.Server, d *Deps)
}

var (
	regMu      sync.Mutex
	registrars []registrar
)

// RegisterGroup records a family's registration function. Called from a family package init function.
func RegisterGroup(group string, fn func(s *mcp.Server, d *Deps)) {
	regMu.Lock()
	defer regMu.Unlock()
	registrars = append(registrars, registrar{group, fn})
}

// ParseGroups parses a comma-separated --groups value. "messaging" implies
// "mqtt"; "all" selects everything.
func ParseGroups(v string) (map[string]bool, error) {
	out := map[string]bool{}
	if strings.TrimSpace(v) == "" {
		for _, g := range DefaultGroups {
			out[g] = true
		}
		return out, nil
	}
	valid := map[string]bool{}
	for _, g := range AllGroups {
		valid[g] = true
	}
	for _, g := range strings.Split(v, ",") {
		g = strings.ToLower(strings.TrimSpace(g))
		switch {
		case g == "":
		case g == "all":
			for _, a := range AllGroups {
				out[a] = true
			}
		case g == "default":
			for _, a := range DefaultGroups {
				out[a] = true
			}
		case valid[g]:
			out[g] = true
			if g == GroupMessaging {
				out[GroupMQTT] = true
			}
		default:
			return nil, fmt.Errorf("unknown tool group %q (valid: %s, all, default)", g, strings.Join(AllGroups, ", "))
		}
	}
	return out, nil
}

// Register adds the tools of the enabled groups to the server.
func Register(s *mcp.Server, d *Deps, groups map[string]bool) {
	registerInfo(s, d, groups)
	regMu.Lock()
	rs := append([]registrar(nil), registrars...)
	regMu.Unlock()
	sort.SliceStable(rs, func(i, j int) bool { return groupIndex(rs[i].group) < groupIndex(rs[j].group) })
	for _, r := range rs {
		if groups[r.group] {
			r.fn(s, d)
		}
	}
}

func groupIndex(g string) int {
	for i, a := range AllGroups {
		if a == g {
			return i
		}
	}
	return len(AllGroups)
}

// Annotation presets.
var (
	// ReadOnly tools fetch or inspect without side effects on the remote.
	ReadOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)}
	// Mutating tools may change remote state (requests, publishes, uploads).
	Mutating = &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), OpenWorldHint: ptr(true)}
	// Local tools only transform input (no network).
	Local = &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}
)

func ptr[T any](v T) *T { return &v }

// Handler is the shape of every tool handler.
type Handler[In any] func(ctx context.Context, req *mcp.CallToolRequest, in In) (any, error)

// Add registers a typed tool. Panics in handlers are converted into tool
// errors so one bad call cannot take the server down.
func Add[In any](s *mcp.Server, d *Deps, name, title, description string, ann *mcp.ToolAnnotations, h Handler[In]) {
	a := *ann
	a.Title = title
	tool := &mcp.Tool{Name: name, Title: title, Description: description, Annotations: &a}
	mcp.AddTool(s, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (res *mcp.CallToolResult, out any, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("internal error in %s: %v\n%s", name, r, firstLines(string(debug.Stack()), 12))
				out = nil
			}
		}()
		out, err = h(ctx, req, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// NewHTTPClient builds a guarded HTTP client for a call.
func (d *Deps) NewHTTPClient(opts types.HTTPOptions, a *auth.Config) (*httpx.Client, error) {
	return d.HTTP.New(opts, a)
}

// Headers converts a header map to http.Header.
func Headers(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

type infoIn struct{}

type infoOut struct {
	Version      string         `json:"version"`
	Groups       []string       `json:"enabled_groups"`
	ReadDirs     []string       `json:"allowed_read_dirs"`
	WriteDirs    []string       `json:"allowed_write_dirs"`
	PrivateMode  string         `json:"private_networks"`
	AllowHosts   []string       `json:"allow_hosts,omitempty"`
	DenyHosts    []string       `json:"deny_hosts,omitempty"`
	AllowPorts   []int          `json:"allow_ports,omitempty"`
	OpenSessions int            `json:"open_sessions"`
	MaxSessions  int            `json:"max_sessions"`
	Limits       map[string]any `json:"limits"`
}

func registerInfo(s *mcp.Server, d *Deps, groups map[string]bool) {
	var gs []string
	for _, g := range AllGroups {
		if groups[g] {
			gs = append(gs, g)
		}
	}
	Add(s, d, "netkit_info", "Server info",
		"Show netkit-mcp configuration: enabled tool groups, directories files may be read from or saved to, network policy and limits. Call this before using file options (body_file, save_to, file payloads).",
		Local, func(ctx context.Context, req *mcp.CallToolRequest, _ infoIn) (any, error) {
			c := d.Cfg
			return infoOut{
				Version:      config.Version,
				Groups:       gs,
				ReadDirs:     nonNil(d.Files.ReadDirs()),
				WriteDirs:    nonNil(d.Files.WriteDirs()),
				PrivateMode:  string(c.PrivateMode),
				AllowHosts:   c.AllowHosts,
				DenyHosts:    c.DenyHosts,
				AllowPorts:   c.AllowPorts,
				OpenSessions: len(d.Sessions.List("")),
				MaxSessions:  c.MaxSessions,
				Limits: map[string]any{
					"default_timeout_seconds": c.DefaultTimeout.Seconds(),
					"max_timeout_seconds":     c.MaxTimeout.Seconds(),
					"max_response_bytes":      c.MaxResponseBytes,
					"max_upload_bytes":        c.MaxUploadBytes,
					"max_download_bytes":      c.MaxDownloadBytes,
					"max_messages":            c.MaxMessages,
					"max_stream_seconds":      c.MaxStreamTime.Seconds(),
					"max_inline_base64_bytes": c.MaxInlineBase64Bytes,
				},
			}, nil
		})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
