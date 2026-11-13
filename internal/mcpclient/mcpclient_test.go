package mcpclient

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestValidateEndpoint(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080/mcp", "https://example.com/mcp"} {
		if err := ValidateEndpoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "npx server", "stdio:///bin/sh", "file:///tmp/x", "ws://example.com", "/usr/bin/server --stdio"} {
		if err := ValidateEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeTransport(t *testing.T) {
	for in, want := range map[string]string{"": TransportStreamable, "HTTP": TransportStreamable, "streamable": TransportStreamable, "sse": TransportSSE} {
		if got, err := NormalizeTransport(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeTransport("stdio"); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("stdio: %v", err)
	}
}

func TestConvertContentBudget(t *testing.T) {
	b := &Budget{Remaining: 10}
	items := ConvertContent([]mcp.Content{
		&mcp.TextContent{Text: "0123456789abcdef"},
		&mcp.ImageContent{MIMEType: "image/png", Data: []byte("png")},
		&mcp.AudioContent{MIMEType: "audio/wav", Data: []byte("wav")},
	}, b)
	if items[0].Text != "0123456789" || !items[0].Truncated {
		t.Fatalf("text: %+v", items[0])
	}
	if items[1].Data != "" || !items[1].Truncated || *items[1].SizeBytes != 3 || items[1].SHA256 == "" {
		t.Fatalf("image: %+v", items[1])
	}
	if items[2].Type != "audio" {
		t.Fatalf("audio: %+v", items[2])
	}
	items = ConvertContent([]mcp.Content{&mcp.ImageContent{MIMEType: "image/png", Data: []byte("png")}}, &Budget{Remaining: 100})
	if items[0].Data != "cG5n" || items[0].Encoding != "base64" {
		t.Fatalf("image: %+v", items[0])
	}
}
