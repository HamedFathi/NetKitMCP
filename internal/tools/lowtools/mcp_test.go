package lowtools_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

const testToken = "s3cret-token"

type echoIn struct {
	Message string `json:"message" jsonschema:"text to echo"`
	Times   int    `json:"times,omitempty"`
}

type echoOut struct {
	Echo  string `json:"echo"`
	Count int    `json:"count"`
}

func remoteServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "remote-test", Version: "9.9"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo a message"},
		func(ctx context.Context, req *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
			n := max(in.Times, 1)
			return nil, echoOut{Echo: strings.Repeat(in.Message, n), Count: n}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "fail", Description: "Always fails"},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
			return nil, nil, errors.New("deliberate failure")
		})
	mcp.AddTool(s, &mcp.Tool{Name: "image", Description: "Returns an image and a resource"},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.ImageContent{MIMEType: "image/png", Data: []byte("\x89PNG fake image bytes")},
				&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "file:///notes.txt", MIMEType: "text/plain", Text: "resource text"}},
				&mcp.ResourceLink{URI: "https://example.com/doc", Name: "doc"},
			}}, nil, nil
		})
	return s
}

func requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Test") != "" && r.Header.Get("X-Test") != "yes" {
			http.Error(w, "bad header", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mcpServers(t *testing.T) (streamURL, sseURL string) {
	t.Helper()
	srv := remoteServer()
	st := httptest.NewServer(requireBearer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)))
	t.Cleanup(st.Close)
	sse := httptest.NewServer(requireBearer(mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv }, nil)))
	t.Cleanup(sse.Close)
	return st.URL + "/mcp", sse.URL + "/sse"
}

var bearer = map[string]any{"type": "bearer", "token": testToken}

func TestMCPClientListTools(t *testing.T) {
	streamURL, sseURL := mcpServers(t)
	h := tooltest.New(t, "mcp")
	for _, tc := range []struct{ url, transport string }{{streamURL, ""}, {sseURL, "sse"}} {
		t.Run(tc.transport, func(t *testing.T) {
			r := h.MustOK("mcp_client_list_tools", map[string]any{"url": tc.url, "transport": tc.transport, "auth": bearer,
				"headers": map[string]string{"X-Test": "yes"}})
			if num(r.Data["count"]) != 3 || r.Data["server"].(map[string]any)["name"] != "remote-test" {
				t.Fatalf("unexpected: %s", r.Raw)
			}
			var echoTool map[string]any
			for _, tt := range r.Data["tools"].([]any) {
				if m := tt.(map[string]any); m["name"] == "echo" {
					echoTool = m
				}
			}
			if echoTool == nil || echoTool["description"] != "Echo a message" {
				t.Fatalf("echo tool: %s", r.Raw)
			}
			props := echoTool["input_schema"].(map[string]any)["properties"].(map[string]any)
			if _, ok := props["message"]; !ok {
				t.Fatalf("schema: %v", echoTool["input_schema"])
			}
			r = h.MustOK("mcp_client_list_tools", map[string]any{"url": tc.url, "transport": tc.transport, "auth": bearer, "compact": true})
			for _, tt := range r.Data["tools"].([]any) {
				if _, ok := tt.(map[string]any)["input_schema"]; ok {
					t.Fatalf("compact output has schemas: %s", r.Raw)
				}
			}
		})
	}
}

func TestMCPClientCallTool(t *testing.T) {
	streamURL, sseURL := mcpServers(t)
	h := tooltest.New(t, "mcp")
	for _, tc := range []struct{ url, transport string }{{streamURL, "streamable_http"}, {sseURL, "sse"}} {
		t.Run(tc.transport, func(t *testing.T) {
			r := h.MustOK("mcp_client_call_tool", map[string]any{"url": tc.url, "transport": tc.transport, "auth": bearer,
				"tool": "echo", "arguments": map[string]any{"message": "hi", "times": 3}})
			if r.Data["is_error"] != false || r.Data["transport"] != tc.transport {
				t.Fatalf("unexpected: %s", r.Raw)
			}
			sc := r.Data["structured_content"].(map[string]any)
			if sc["echo"] != "hihihi" || num(sc["count"]) != 3 {
				t.Fatalf("structured: %v", sc)
			}
			content := r.Data["content"].([]any)
			if len(content) == 0 || content[0].(map[string]any)["type"] != "text" || !strings.Contains(content[0].(map[string]any)["text"].(string), "hihihi") {
				t.Fatalf("content: %v", content)
			}

			// A remote tool error is a successful result with is_error=true.
			r = h.MustOK("mcp_client_call_tool", map[string]any{"url": tc.url, "transport": tc.transport, "auth": bearer, "tool": "fail"})
			if r.Data["is_error"] != true || !strings.Contains(fmt.Sprint(r.Data["content"]), "deliberate failure") {
				t.Fatalf("fail: %s", r.Raw)
			}

			r = h.MustOK("mcp_client_call_tool", map[string]any{"url": tc.url, "transport": tc.transport, "auth": bearer, "tool": "image"})
			items := r.Data["content"].([]any)
			img, res, link := items[0].(map[string]any), items[1].(map[string]any), items[2].(map[string]any)
			if img["type"] != "image" || img["mime_type"] != "image/png" || img["encoding"] != "base64" || img["data"] == "" || img["sha256"] == "" {
				t.Fatalf("image: %v", img)
			}
			if res["type"] != "resource" || res["text"] != "resource text" || res["uri"] != "file:///notes.txt" {
				t.Fatalf("resource: %v", res)
			}
			if link["type"] != "resource_link" || link["uri"] != "https://example.com/doc" {
				t.Fatalf("link: %v", link)
			}
		})
	}
}

func TestMCPClientErrors(t *testing.T) {
	streamURL, sseURL := mcpServers(t)
	h := tooltest.New(t, "mcp")
	// Missing credentials.
	h.MustFail("mcp_client_list_tools", map[string]any{"url": streamURL}, "set auth")
	h.MustFail("mcp_client_call_tool", map[string]any{"url": sseURL, "transport": "sse", "tool": "echo"}, "")
	// Unknown remote tool is a protocol error -> tool error.
	h.MustFail("mcp_client_call_tool", map[string]any{"url": streamURL, "auth": bearer, "tool": "nope"}, "nope")
	// Stdio / command-style inputs are rejected.
	h.MustFail("mcp_client_list_tools", map[string]any{"url": "npx -y @modelcontextprotocol/server-everything"}, "not supported")
	h.MustFail("mcp_client_list_tools", map[string]any{"url": "stdio:///usr/bin/server"}, "not supported")
	h.MustFail("mcp_client_list_tools", map[string]any{"url": streamURL, "transport": "stdio"}, "not supported")
	h.MustFail("mcp_client_call_tool", map[string]any{"url": streamURL, "tool": "echo", "command": "rm", "args": []string{"-rf", "/"}}, "additional properties")
	h.MustFail("mcp_client_call_tool", map[string]any{"url": streamURL, "auth": bearer}, "tool")

	// SSRF guard applies to the MCP endpoint.
	hg := tooltest.New(t, "mcp", tooltest.WithPrivateMode(config.PrivateOptIn))
	hg.MustFail("mcp_client_list_tools", map[string]any{"url": streamURL, "auth": bearer}, "allow_private")
	hg.MustOK("mcp_client_list_tools", map[string]any{"url": streamURL, "auth": bearer, "allow_private": true})
}

func TestToolGroups(t *testing.T) {
	low := strings.Join(tooltest.New(t, "lowlevel").ListTools(), ",")
	for _, n := range []string{"tcp_request", "udp_request", "dns_query", "tls_inspect"} {
		if !strings.Contains(low, n) {
			t.Fatalf("lowlevel group misses %s: %s", n, low)
		}
	}
	if strings.Contains(low, "mcp_client") {
		t.Fatalf("mcp tools registered in lowlevel group: %s", low)
	}
	m := strings.Join(tooltest.New(t, "mcp").ListTools(), ",")
	if !strings.Contains(m, "mcp_client_list_tools") || !strings.Contains(m, "mcp_client_call_tool") || strings.Contains(m, "tcp_request") {
		t.Fatalf("mcp group: %s", m)
	}
}
