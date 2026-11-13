package soaptools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/soap"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupSOAP, register) }

// WSDLSource selects where the WSDL comes from (at most one field).
type WSDLSource struct {
	WSDLURL  string `json:"wsdl_url,omitempty" jsonschema:"URL of a WSDL 1.1 document; imports are resolved relative to it"`
	WSDLFile string `json:"wsdl_file,omitempty" jsonschema:"path of a WSDL file inside an allowed read directory; imports are resolved relative to it"`
	WSDL     string `json:"wsdl,omitempty" jsonschema:"inline WSDL XML (only absolute http(s) imports can be resolved)"`
}

func (s WSDLSource) count() int {
	n := 0
	for _, v := range []string{s.WSDLURL, s.WSDLFile, s.WSDL} {
		if strings.TrimSpace(v) != "" {
			n++
		}
	}
	return n
}

type describeIn struct {
	WSDLSource
	Operation string `json:"operation,omitempty" jsonschema:"describe only this operation in detail (parts, input/output shapes, faults)"`
	Service   string `json:"service,omitempty" jsonschema:"service name (narrows the operation lookup)"`
	Port      string `json:"port,omitempty" jsonschema:"port name (narrows the operation lookup)"`
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"HTTP auth for fetching the WSDL and its imports"`
}

func register(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "soap_describe", "Describe a SOAP service (WSDL)",
		"Parse a WSDL 1.1 (wsdl_url, wsdl_file or inline wsdl; wsdl:import, xs:import and xs:include are resolved) and list services, ports "+
			"(SOAP 1.1/1.2, document/rpc, endpoint), operations (soapAction, literal/encoded) and JSON skeletons of each operation's input and output "+
			"derived from the XML Schema. Skeleton keys ending in '?' are optional, '@x' are attributes, [ ] means repeated. "+
			"Set operation for one operation in detail. Use the input skeleton as args for soap_request. WSDL 2.0 is not supported.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in describeIn) (any, error) {
			if in.count() == 0 {
				return nil, errors.New("set one of wsdl_url, wsdl_file or wsdl")
			}
			defs, err := loadWSDL(ctx, d, in.WSDLSource, in.HTTPOptions, in.Auth)
			if err != nil {
				return nil, err
			}
			return defs.Describe(in.Operation, in.Service, in.Port)
		})
	registerRequest(s, d)
}

// loadWSDL loads a WSDL with import resolution. URL documents go through
// the guarded HTTP client; files through the read policy.
func loadWSDL(ctx context.Context, d *tools.Deps, src WSDLSource, opts types.HTTPOptions, a *auth.Config) (*soap.Definitions, error) {
	if src.count() > 1 {
		return nil, errors.New("set only one of wsdl_url, wsdl_file or wsdl")
	}
	// WSDL documents may be larger than the inline response default.
	maxBytes := d.Cfg.MaxResponseBytes
	var client *httpx.Client
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	fetchOpts := opts
	fetchOpts.MaxResponseBytes = 0
	fetch := soap.FetchFunc(func(ctx context.Context, loc soap.Location) ([]byte, error) {
		if loc.File != "" {
			return d.Files.ReadSmall(loc.File, maxBytes)
		}
		if client == nil {
			c, err := d.NewHTTPClient(fetchOpts, httpAuth(a))
			if err != nil {
				return nil, err
			}
			client = c
		}
		return fetchURL(ctx, client, loc.URL, maxBytes)
	})
	lo := soap.LoadOptions{}
	switch {
	case src.WSDLURL != "":
		data, err := fetch(ctx, soap.Location{URL: src.WSDLURL})
		if err != nil {
			return nil, fmt.Errorf("fetching WSDL: %w", err)
		}
		return soap.Load(ctx, data, soap.Location{URL: src.WSDLURL}, fetch, lo)
	case src.WSDLFile != "":
		real, err := d.Files.ResolveRead(src.WSDLFile)
		if err != nil {
			return nil, err
		}
		data, err := d.Files.ReadSmall(real, maxBytes)
		if err != nil {
			return nil, err
		}
		return soap.Load(ctx, data, soap.Location{File: real}, fetch, lo)
	default:
		return soap.Load(ctx, []byte(src.WSDL), soap.Location{}, fetch, lo)
	}
}

// httpAuth returns the auth config to apply at the HTTP layer (ws_security
// is a SOAP header, which the HTTP transport ignores).
func httpAuth(a *auth.Config) *auth.Config {
	if a == nil || a.Kind() == "none" {
		return nil
	}
	return a
}

func fetchURL(ctx context.Context, c *httpx.Client, url string, maxBytes int64) ([]byte, error) {
	ctx, cancel := c.Context(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/xml, application/xml, application/wsdl+xml, */*")
	req.Header.Set("User-Agent", c.UserAgent())
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: HTTP %s", redact.URL(url), resp.Status)
	}
	data, _, truncated, err := httpx.ReadLimited(resp.Body, maxBytes)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("%s is larger than %d bytes", redact.URL(url), maxBytes)
	}
	return data, nil
}
