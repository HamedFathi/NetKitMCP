package lowtools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/mcpclient"
	"github.com/HamedFathi/NetKitMCP/internal/netx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() {
	tools.RegisterGroup(tools.GroupMCP, func(s *mcp.Server, d *tools.Deps) {
		registerMCPList(s, d)
		registerMCPCall(s, d)
	})
}

// mcpConn are the connection arguments shared by the MCP client tools.
type mcpConn struct {
	URL       string            `json:"url" jsonschema:"HTTP(S) endpoint of the remote MCP server, e.g. https://example.com/mcp (stdio commands are not supported)"`
	Transport string            `json:"transport,omitempty" jsonschema:"streamable_http (default) or sse (legacy HTTP+SSE; url is then the SSE endpoint)"`
	Headers   map[string]string `json:"headers,omitempty" jsonschema:"extra HTTP headers sent on every request"`
	Auth      *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

func (c *mcpConn) connect(ctx context.Context, d *tools.Deps) (*mcp.ClientSession, func(), error) {
	if err := mcpclient.ValidateEndpoint(c.URL); err != nil {
		return nil, nil, err
	}
	if _, err := mcpclient.NormalizeTransport(c.Transport); err != nil {
		return nil, nil, err
	}
	hc, err := d.NewHTTPClient(c.HTTPOptions, c.Auth)
	if err != nil {
		return nil, nil, err
	}
	cs, err := mcpclient.Connect(ctx, mcpclient.Options{
		Endpoint: c.URL, Transport: c.Transport, HTTPClient: hc.Client, Headers: tools.Headers(c.Headers),
	})
	if err != nil {
		hc.Close()
		return nil, nil, err
	}
	return cs, func() { cs.Close(); hc.Close() }, nil
}

func (c *mcpConn) warnings() []string {
	if c.InsecureSkipVerify {
		return []string{insecureWarning}
	}
	return nil
}

type mcpListIn struct {
	mcpConn
	Compact  bool `json:"compact,omitempty" jsonschema:"return only tool names and descriptions (no schemas)"`
	MaxPages int  `json:"max_pages,omitempty" jsonschema:"maximum tools/list pages to fetch (default 20)"`
}

type remoteTool struct {
	Name         string               `json:"name"`
	Title        string               `json:"title,omitempty"`
	Description  string               `json:"description,omitempty"`
	InputSchema  any                  `json:"input_schema,omitempty"`
	OutputSchema any                  `json:"output_schema,omitempty"`
	Annotations  *mcp.ToolAnnotations `json:"annotations,omitempty"`
}

type mcpListOut struct {
	Server    *mcpclient.ServerInfo `json:"server,omitempty"`
	Transport string                `json:"transport"`
	Count     int                   `json:"count"`
	Pages     int                   `json:"pages"`
	MorePages bool                  `json:"more_pages,omitempty"`
	Tools     []remoteTool          `json:"tools"`
	TimingMS  struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Warnings []string `json:"warnings,omitempty"`
}

func registerMCPList(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "mcp_client_list_tools", "List remote MCP tools",
		"Connect to a remote MCP server over streamable HTTP (default) or legacy SSE and list its tools (name, title, description, input schema), "+
			"following pagination. compact=true returns names and descriptions only. Supports the shared auth object (bearer, oauth2, ...), headers and TLS options. "+
			"Spawning stdio servers is not supported.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in mcpListIn) (any, error) {
			start := time.Now()
			ctx, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(in.TimeoutSeconds))
			defer cancel()
			cs, closeFn, err := in.connect(ctx, d)
			if err != nil {
				return nil, err
			}
			defer closeFn()
			maxPages := in.MaxPages
			if maxPages <= 0 {
				maxPages = 20
			}
			list, pages, more, err := mcpclient.ListAll(ctx, cs, min(maxPages, 200))
			if err != nil {
				return nil, err
			}
			tname, _ := mcpclient.NormalizeTransport(in.Transport)
			out := &mcpListOut{Server: mcpclient.Server(cs), Transport: tname, Count: len(list), Pages: pages, MorePages: more,
				Tools: []remoteTool{}, Warnings: in.warnings()}
			for _, t := range list {
				rt := remoteTool{Name: t.Name, Title: t.Title, Description: t.Description}
				if rt.Title == "" && t.Annotations != nil {
					rt.Title = t.Annotations.Title
				}
				if !in.Compact {
					rt.InputSchema = t.InputSchema
					rt.OutputSchema = t.OutputSchema
					rt.Annotations = t.Annotations
				}
				out.Tools = append(out.Tools, rt)
			}
			if more {
				out.Warnings = append(out.Warnings, fmt.Sprintf("stopped after %d pages; raise max_pages to fetch more", pages))
			}
			out.TimingMS.Total = netx.MS(time.Since(start))
			return out, nil
		})
}

type mcpCallIn struct {
	mcpConn
	Tool      string         `json:"tool" jsonschema:"name of the remote tool to call"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"arguments object for the remote tool"`
}

type mcpCallOut struct {
	Server            *mcpclient.ServerInfo   `json:"server,omitempty"`
	Transport         string                  `json:"transport"`
	Tool              string                  `json:"tool"`
	IsError           bool                    `json:"is_error"`
	Content           []mcpclient.ContentItem `json:"content"`
	StructuredContent any                     `json:"structured_content,omitempty"`
	Meta              map[string]any          `json:"meta,omitempty"`
	Truncated         bool                    `json:"truncated,omitempty"`
	TimingMS          struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Warnings []string `json:"warnings,omitempty"`
}

func registerMCPCall(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "mcp_client_call_tool", "Call remote MCP tool",
		"Connect to a remote MCP server over streamable HTTP (default) or legacy SSE and call one tool with arguments. Returns the content items "+
			"(text as text; images, audio and blobs as base64 with size and sha256; resources and links), structured_content and is_error. "+
			"A remote tool failure is a successful result with is_error=true. Use mcp_client_list_tools first to learn tool names and schemas. "+
			"Spawning stdio servers is not supported.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in mcpCallIn) (any, error) {
			if strings.TrimSpace(in.Tool) == "" {
				return nil, fmt.Errorf("tool is required (use mcp_client_list_tools to see what the server offers)")
			}
			start := time.Now()
			ctx, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(in.TimeoutSeconds))
			defer cancel()
			cs, closeFn, err := in.connect(ctx, d)
			if err != nil {
				return nil, err
			}
			defer closeFn()
			args := in.Arguments
			if args == nil {
				args = map[string]any{}
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: in.Tool, Arguments: args})
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("remote tool %q did not finish within the timeout: %w", in.Tool, err)
				}
				return nil, fmt.Errorf("tools/call %q: %w", in.Tool, err)
			}
			tname, _ := mcpclient.NormalizeTransport(in.Transport)
			budget := &mcpclient.Budget{Remaining: d.Cfg.ResponseBytes(in.MaxResponseBytes)}
			out := &mcpCallOut{Server: mcpclient.Server(cs), Transport: tname, Tool: in.Tool, IsError: res.IsError,
				Content: mcpclient.ConvertContent(res.Content, budget), StructuredContent: res.StructuredContent,
				Warnings: in.warnings()}
			if len(res.Meta) > 0 {
				out.Meta = res.Meta
			}
			for _, c := range out.Content {
				if c.Truncated {
					out.Truncated = true
					out.Warnings = append(out.Warnings, "some content exceeded max_response_bytes and was truncated or omitted (see size_bytes and sha256)")
					break
				}
			}
			out.TimingMS.Total = netx.MS(time.Since(start))
			return out, nil
		})
}
