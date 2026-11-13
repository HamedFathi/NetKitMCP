package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

// The tool reference in README.md is generated from the live tool schemas so
// it can never drift from the code. Regenerate it with:
//
//	go test -run TestReadmeToolReference -update-readme .
var updateReadme = flag.Bool("update-readme", false, "rewrite the generated tool reference in README.md")

const (
	refStart = "<!-- BEGIN GENERATED TOOL REFERENCE (go test -run TestReadmeToolReference -update-readme .) -->"
	refEnd   = "<!-- END GENERATED TOOL REFERENCE -->"
)

type schema struct {
	Type                 any                `json:"type"`
	Description          string             `json:"description"`
	Properties           map[string]*schema `json:"properties"`
	Required             []string           `json:"required"`
	Items                *schema            `json:"items"`
	AdditionalProperties any                `json:"additionalProperties"`
	Enum                 []any              `json:"enum"`
}

// UnmarshalJSON accepts boolean schemas (true = any value).
func (s *schema) UnmarshalJSON(b []byte) error {
	if t := string(bytes.TrimSpace(b)); t == "true" || t == "false" {
		return nil
	}
	type plain schema
	return json.Unmarshal(b, (*plain)(s))
}

// Options shared by many tools are documented once, under "Common options".
// A property is folded into its set only when its description is the
// canonical one; tool-specific variants stay in the tool's own table.
var commonSets = []struct {
	name, anchor string
	props        map[string]string
}{
	{"network options", "#common-options", map[string]string{
		"insecure_skip_verify": "skip server certificate verification (flagged in the result)",
		"ca_cert":              "extra CA certificate(s): inline PEM or file path",
		"client_cert":          "client certificate for mTLS: inline PEM or file path",
		"client_key":           "client private key for mTLS: inline PEM or file path",
		"server_name":          "override TLS SNI / verification name",
		"timeout_seconds":      "overall timeout in seconds (default 30)",
		"allow_private":        "permit loopback/private/link-local targets (subject to server policy)",
	}},
	{"HTTP options", "#common-options", map[string]string{
		"follow_redirects":   "follow redirects (default true)",
		"max_redirects":      "maximum redirects to follow (default 10)",
		"proxy":              "proxy URL (http, https or socks5)",
		"max_response_bytes": "maximum response body bytes returned inline (default 1 MiB)",
		"http_version":       "1.1, 2 or 3 (default: negotiate 1.1/2)",
	}},
	{"stream limits", "#common-options", map[string]string{
		"max_messages":         "stop after this many received messages (default 100)",
		"max_duration_seconds": "stop after this many seconds (default 10)",
		"idle_timeout_seconds": "stop when no message arrives for this many seconds (default: none)",
	}},
}

var groupTitles = map[string]string{
	tools.GroupHTTP:      "HTTP and API protocols",
	tools.GroupGRPC:      "gRPC, gRPC-Web and Connect",
	tools.GroupWS:        "WebSocket and Socket.IO",
	tools.GroupSOAP:      "SOAP and WSDL",
	tools.GroupMQTT:      "MQTT",
	tools.GroupMessaging: "Message brokers and IoT",
	tools.GroupTransfer:  "File transfer",
	tools.GroupLowLevel:  "Low-level network",
	tools.GroupMCP:       "MCP client",
	tools.GroupAuth:      "OAuth2 helpers",
}

func TestReadmeToolReference(t *testing.T) {
	ref := renderToolReference(t)
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(readme), "\r\n", "\n")
	i, j := strings.Index(s, refStart), strings.Index(s, refEnd)
	if i < 0 || j < i {
		t.Fatalf("README.md is missing the %q / %q markers", refStart, refEnd)
	}
	updated := s[:i+len(refStart)] + "\n" + ref + s[j:]
	if updated == s {
		return
	}
	if *updateReadme {
		if err := os.WriteFile("README.md", []byte(updated), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("README.md tool reference regenerated")
		return
	}
	t.Fatal("README.md tool reference is out of date; run: go test -run TestReadmeToolReference -update-readme .")
}

func renderToolReference(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	seen := map[string]bool{"netkit_info": true}
	var authSchema *schema
	for _, g := range tools.AllGroups {
		list := groupTools(t, g)
		var mine []*mcp.Tool
		for _, tl := range list {
			if !seen[tl.Name] {
				mine = append(mine, tl)
			}
		}
		for _, tl := range mine {
			seen[tl.Name] = true
		}
		def := ""
		for _, dg := range tools.DefaultGroups {
			if dg == g {
				def = ", on by default"
			}
		}
		fmt.Fprintf(&b, "\n### `%s`: %s\n\n%d tools%s.\n", g, groupTitles[g], len(mine), def)
		for _, tl := range mine {
			sc := toSchema(t, tl.InputSchema)
			if a := sc.Properties["auth"]; a != nil && authSchema == nil {
				authSchema = a
			}
			renderTool(&b, tl, sc)
		}
	}
	// netkit_info is registered with every group.
	info := groupTools(t, tools.GroupHTTP)
	for _, tl := range info {
		if tl.Name == "netkit_info" {
			fmt.Fprintf(&b, "\n### Always available\n")
			renderTool(&b, tl, toSchema(t, tl.InputSchema))
		}
	}
	if authSchema != nil {
		fmt.Fprintf(&b, "\n### The `auth` object\n\nEvery field of the shared `auth` argument. Set `type`, then only the fields that type uses (see [Authentication](#authentication)).\n\n")
		fmt.Fprintf(&b, "| Field | Type | Description |\n|---|---|---|\n")
		var rows [][3]string
		flatten(authSchema, "", &rows, nil, 0)
		for _, r := range rows {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r[0], r[1], r[2])
		}
	}
	return b.String()
}

func renderTool(b *bytes.Buffer, tl *mcp.Tool, sc *schema) {
	kind := "mutating"
	if a := tl.Annotations; a != nil {
		switch {
		case a.OpenWorldHint != nil && !*a.OpenWorldHint:
			kind = "local, no network"
		case a.ReadOnlyHint:
			kind = "read-only"
		}
	}
	fmt.Fprintf(b, "\n<details>\n<summary><code>%s</code>: %s <sub>(%s)</sub></summary>\n\n%s\n\n", tl.Name, tl.Title, kind, escape(tl.Description))
	var rows [][4]string
	var uses []string
	required := set(sc.Required)
	names := keys(sc.Properties)
	folded := map[string]bool{}
	for _, cs := range commonSets {
		n := 0
		for k, desc := range cs.props {
			if p := sc.Properties[k]; p != nil && p.Description == desc {
				folded[k] = true
				n++
			}
		}
		if n > 0 {
			uses = append(uses, fmt.Sprintf("[%s](%s)", cs.name, cs.anchor))
		}
	}
	for _, k := range names {
		if folded[k] {
			continue
		}
		p := sc.Properties[k]
		req := ""
		if required[k] {
			req = "yes"
		}
		if k == "auth" {
			rows = append(rows, [4]string{"auth", "object", req, "credentials; see [The `auth` object](#the-auth-object)"})
			continue
		}
		rows = append(rows, [4]string{k, typeOf(p), req, escape(p.Description)})
		var sub [][3]string
		if p.Items != nil && len(p.Items.Properties) > 0 {
			flatten(p.Items, k+"[].", &sub, set(p.Items.Required), 1)
		} else if len(p.Properties) > 0 {
			flatten(p, k+".", &sub, set(p.Required), 1)
		}
		for _, s := range sub {
			rows = append(rows, [4]string{s[0], s[1], "", s[2]})
		}
	}
	if len(rows) == 0 {
		b.WriteString("No arguments.\n")
	} else {
		b.WriteString("| Argument | Type | Required | Description |\n|---|---|:---:|---|\n")
		for _, r := range rows {
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", r[0], r[1], r[2], r[3])
		}
	}
	if n := len(uses); n > 0 {
		list := uses[0]
		if n > 1 {
			list = strings.Join(uses[:n-1], ", ") + " and " + uses[n-1]
		}
		fmt.Fprintf(b, "\nAlso accepts the %s.\n", list)
	}
	b.WriteString("\n</details>\n")
}

// flatten lists nested properties with dotted paths.
func flatten(sc *schema, prefix string, rows *[][3]string, required map[string]bool, depth int) {
	for _, k := range keys(sc.Properties) {
		p := sc.Properties[k]
		desc := escape(p.Description)
		if required[k] {
			desc = "**required.** " + desc
		}
		*rows = append(*rows, [3]string{prefix + k, typeOf(p), desc})
		if depth >= 4 {
			continue
		}
		if p.Items != nil && len(p.Items.Properties) > 0 {
			flatten(p.Items, prefix+k+"[].", rows, set(p.Items.Required), depth+1)
		} else if len(p.Properties) > 0 {
			flatten(p, prefix+k+".", rows, set(p.Required), depth+1)
		}
	}
}

func typeOf(p *schema) string {
	var ts []string
	switch v := p.Type.(type) {
	case string:
		ts = []string{v}
	case []any:
		for _, x := range v {
			if s, _ := x.(string); s != "null" {
				ts = append(ts, s)
			}
		}
	}
	if len(ts) == 0 {
		return "any"
	}
	t := strings.Join(ts, " \\| ")
	switch t {
	case "array":
		if p.Items != nil {
			it := typeOf(p.Items)
			if len(p.Items.Properties) > 0 {
				it = "object"
			}
			return it + "[]"
		}
	case "object":
		if len(p.Properties) == 0 {
			if ap, ok := p.AdditionalProperties.(map[string]any); ok {
				if at, _ := ap["type"].(string); at != "" {
					return "map&lt;string, " + at + "&gt;"
				}
			}
			return "object"
		}
	}
	return t
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return strings.ReplaceAll(s, ">", "&gt;")
}

func keys(m map[string]*schema) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func toSchema(t *testing.T, v any) *schema {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var s schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// groupTools returns the tools one group registers, in name order.
func groupTools(t *testing.T, group string) []*mcp.Tool {
	t.Helper()
	cs := startServer(t, "--groups", group)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out []*mcp.Tool
	for tl, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
