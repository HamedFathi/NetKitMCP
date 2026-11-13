package httptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/curlparse"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

type curlIn struct {
	Command string `json:"command" jsonschema:"the curl command line as pasted (bash, cmd or PowerShell quoting)"`
}

func handleCurl(d *tools.Deps) tools.Handler[curlIn] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in curlIn) (any, error) {
		if strings.TrimSpace(in.Command) == "" {
			return nil, fmt.Errorf("command is required")
		}
		res, err := curlparse.Parse(in.Command)
		if err != nil {
			return nil, fmt.Errorf("parsing curl command: %w", err)
		}
		// Point out file references the server cannot read or write.
		check := func(arg, p string, write bool) {
			var err error
			if write {
				_, err = d.Files.ResolveWrite(p, false)
			} else {
				_, err = d.Files.ResolveRead(p)
			}
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s %q: %v (relative paths resolve against the first allowed directory; see netkit_info)", arg, p, err))
			}
		}
		a := res.Arguments
		if p, ok := a["body_file"].(string); ok {
			check("body_file", p, false)
		}
		if p, ok := a["file"].(string); ok {
			check("file", p, false)
		}
		if parts, ok := a["parts"].([]map[string]any); ok {
			for i, part := range parts {
				if p, ok := part["file"].(string); ok {
					check(fmt.Sprintf("parts[%d].file", i), p, false)
				}
			}
		}
		if p, ok := a["save_to"].(string); ok {
			check("save_to", p, true)
		}
		if u, ok := a["url"].(string); ok && redact.URL(u) != u {
			res.Warnings = append(res.Warnings, "the URL contains credentials or signed parameters; treat these arguments as secret")
		}
		return res, nil
	}
}
