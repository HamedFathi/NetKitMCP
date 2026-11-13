package soaptools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/soap"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type requestIn struct {
	WSDLSource
	Operation   string            `json:"operation,omitempty" jsonschema:"operation name from the WSDL (requires wsdl_url, wsdl_file or wsdl)"`
	Service     string            `json:"service,omitempty" jsonschema:"service name when several services define the operation"`
	Port        string            `json:"port,omitempty" jsonschema:"port name (e.g. pick the SOAP 1.2 port)"`
	Args        any               `json:"args,omitempty" jsonschema:"operation input as JSON, shaped like the soap_describe input skeleton"`
	RawBody     string            `json:"raw_body,omitempty" jsonschema:"raw XML instead of args: a full soap Envelope, or Body content to wrap"`
	Endpoint    string            `json:"endpoint,omitempty" jsonschema:"endpoint URL (default: the port address from the WSDL)"`
	SOAPVersion string            `json:"soap_version,omitempty" jsonschema:"1.1 (text/xml + SOAPAction header) or 1.2 (application/soap+xml; action=...); default from the binding, else 1.1"`
	SOAPAction  *string           `json:"soap_action,omitempty" jsonschema:"override the SOAP action (default from the WSDL)"`
	SOAPHeaders []string          `json:"soap_headers,omitempty" jsonschema:"raw XML header blocks to put in soap:Header (declare their namespaces)"`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"extra HTTP headers"`
	Typed       *bool             `json:"typed_response,omitempty" jsonschema:"type response values (numbers, booleans, arrays) using the WSDL output shape (default true)"`
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"HTTP auth, or type ws_security (username, password, ws_security{password_type text|digest, timestamp, ttl_seconds, must_understand}) for a WS-Security UsernameToken header"`
}

type sentInfo struct {
	Endpoint    string            `json:"endpoint"`
	Operation   string            `json:"operation,omitempty"`
	SOAPVersion string            `json:"soap_version"`
	SOAPAction  string            `json:"soap_action"`
	Headers     map[string]string `json:"headers"`
	Envelope    string            `json:"envelope"`
}

type requestOut struct {
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type,omitempty"`
	SOAPVersion string            `json:"soap_version,omitempty"`
	Fault       *soap.Fault       `json:"fault,omitempty"`
	Header      any               `json:"header,omitempty"`
	Body        any               `json:"body"`
	RawXML      string            `json:"raw_xml"`
	RawEncoding string            `json:"raw_encoding,omitempty"`
	SizeBytes   int64             `json:"size_bytes"`
	Truncated   bool              `json:"truncated"`
	FinalURL    string            `json:"final_url"`
	Protocol    string            `json:"protocol"`
	TimingMS    types.Timing      `json:"timing_ms"`
	TLS         *types.TLSInfo    `json:"tls,omitempty"`
	Request     sentInfo          `json:"request"`
	Warnings    []string          `json:"warnings,omitempty"`
}

func registerRequest(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "soap_request", "Call a SOAP operation",
		"Call a SOAP operation by name with JSON args (built into a document/literal or rpc body from the WSDL, with correct namespaces), "+
			"or send raw_body XML (a full Envelope or Body content). Supports SOAP 1.1 and 1.2, SOAPAction, custom soap_headers, HTTP auth and "+
			"WS-Security UsernameToken (text or digest) with Timestamp (auth.type=ws_security). Returns HTTP status, the Body as JSON, "+
			"the raw XML (truncated per max_response_bytes) and a parsed fault (SOAP faults are results, not errors). "+
			"MTOM/XOP attachments and WS-Security signing/encryption are not supported.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in requestIn) (any, error) {
			return doRequest(ctx, d, in)
		})
}

func doRequest(ctx context.Context, d *tools.Deps, in requestIn) (*requestOut, error) {
	version, err := soap.NormalizeVersion(in.SOAPVersion)
	if err != nil {
		return nil, err
	}
	if in.Operation == "" && strings.TrimSpace(in.RawBody) == "" {
		return nil, errors.New("set operation (with a WSDL) or raw_body")
	}
	if in.Operation != "" && in.count() == 0 {
		return nil, errors.New("operation requires a WSDL: set wsdl_url, wsdl_file or wsdl (or send raw_body with endpoint)")
	}
	for i, h := range in.SOAPHeaders {
		if err := soap.CheckFragment(h); err != nil {
			return nil, fmt.Errorf("soap_headers[%d] is not well-formed XML: %w", i, err)
		}
	}
	wsSec, err := wsSecurity(in.Auth)
	if err != nil {
		return nil, err
	}
	if in.Auth != nil {
		if ext := in.Auth.WSSec; ext != nil && in.Auth.Kind() != "ws_security" {
			return nil, errors.New("auth.ws_security is set but auth.type is not ws_security")
		}
	}

	var defs *soap.Definitions
	var warnings []string
	if in.count() > 0 {
		defs, err = loadWSDL(ctx, d, in.WSDLSource, in.HTTPOptions, in.Auth)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, defs.Warnings...)
	}

	prep, err := soap.Prepare(soap.PrepareOptions{
		Defs: defs, Operation: in.Operation, Service: in.Service, Port: in.Port,
		Args: in.Args, RawBody: in.RawBody, Version: version, SOAPAction: in.SOAPAction,
		Headers: func(v string) ([]string, error) {
			var hs []string
			if wsSec != nil {
				h, err := wsSec.Header(v)
				if err != nil {
					return nil, err
				}
				hs = append(hs, h)
			}
			return append(hs, in.SOAPHeaders...), nil
		},
	})
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, prep.Warnings...)

	endpoint := in.Endpoint
	if endpoint == "" && prep.Op != nil {
		endpoint = prep.Op.Address
	}
	if endpoint == "" {
		return nil, errors.New("no endpoint: set endpoint (the WSDL port has no soap:address)")
	}

	c, err := d.NewHTTPClient(in.HTTPOptions, httpAuth(in.Auth))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cctx, cancel := c.Context(ctx)
	defer cancel()
	hreq, err := http.NewRequestWithContext(cctx, http.MethodPost, endpoint, strings.NewReader(prep.Envelope))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	hreq.Header.Set("Content-Type", prep.ContentType)
	if v := prep.SOAPActionHeader(); v != "" {
		hreq.Header.Set("SOAPAction", v)
	}
	hreq.Header.Set("Accept", "text/xml, application/soap+xml, multipart/related, */*")
	for k, v := range in.Headers {
		hreq.Header.Set(k, v)
	}
	if hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", c.UserAgent())
	}
	sent := sentInfo{
		Endpoint: redact.URL(endpoint), SOAPVersion: prep.Version, SOAPAction: prep.Action,
		Headers: redact.Headers(hreq.Header), Envelope: redact.Text(prep.Envelope),
	}
	if prep.Op != nil {
		sent.Operation = prep.Op.BOp.Name
	}

	// Read up to the server ceiling so the envelope can be parsed; the raw
	// XML echoed back is truncated to the per-call limit below.
	resp, err := c.Do(hreq, httpx.ReadOptions{MaxBytes: d.Cfg.MaxResponseBytes})
	if err != nil {
		if httpx.IsTimeout(err) {
			return nil, fmt.Errorf("SOAP request timed out after %s (raise timeout_seconds): %w", c.Timeout.Round(time.Millisecond), err)
		}
		return nil, fmt.Errorf("SOAP request failed: %w", err)
	}
	out := &requestOut{
		Status: resp.Status, StatusText: resp.StatusText, Headers: resp.Headers, ContentType: resp.ContentType,
		SizeBytes: resp.SizeBytes, Truncated: resp.Truncated, FinalURL: redact.URL(resp.FinalURL), Protocol: resp.Protocol,
		TimingMS: resp.TimingMS, TLS: resp.TLS, Request: sent,
	}
	warnings = append(warnings, resp.Warnings...)

	var raw []byte
	if resp.BodyEncoding == "base64" {
		raw, _ = types.DecodeBase64(resp.Body)
	} else {
		// A server that echoes the request back would leak the credential
		// into raw_xml and the parsed header, so mask it before parsing.
		body := redact.Text(resp.Body)
		if in.Auth != nil && len(in.Auth.Password) >= 4 {
			body = strings.ReplaceAll(body, in.Auth.Password, "***")
		}
		raw = []byte(body)
	}
	ct := strings.ToLower(resp.ContentType)
	switch {
	case strings.HasPrefix(ct, "multipart/related"):
		warnings = append(warnings, "the response is multipart/related (MTOM/XOP or SwA), which is not supported; see raw_xml")
	case resp.Truncated:
		warnings = append(warnings, fmt.Sprintf("the response exceeded %d bytes and was not parsed", d.Cfg.MaxResponseBytes))
	case len(strings.TrimSpace(string(raw))) == 0:
		// Empty body (e.g. one-way operation answered with 202).
	default:
		var outFields []*soap.Field
		rpc := false
		if prep.Op != nil {
			rpc = prep.Op.Style() == "rpc"
			if types.BoolDefault(in.Typed, true) {
				outFields = defs.OutputFields(prep.Op)
			}
		}
		parsed, perr := soap.ParseResponse(raw, outFields, rpc)
		if perr != nil {
			warnings = append(warnings, "could not parse the response as SOAP: "+perr.Error())
		} else {
			out.SOAPVersion = parsed.SOAPVersion
			out.Fault = parsed.Fault
			out.Header = parsed.Header
			out.Body = parsed.Body
			if parsed.SOAPVersion != prep.Version {
				warnings = append(warnings, fmt.Sprintf("sent SOAP %s but the response is SOAP %s", prep.Version, parsed.SOAPVersion))
			}
		}
		if defs != nil {
			warnings = appendNew(warnings, defs.Schemas.Warnings...)
		}
	}

	limit := c.MaxResponseBytes
	if int64(len(raw)) > limit {
		cut := int(limit)
		for cut > 0 && !utf8.RuneStart(raw[cut]) {
			cut--
		}
		raw = raw[:cut]
		out.Truncated = true
		warnings = append(warnings, fmt.Sprintf("raw_xml truncated to %d bytes (raise max_response_bytes to see more)", limit))
	}
	out.RawXML, out.RawEncoding = types.EncodeBody(raw, resp.ContentType)
	if out.RawEncoding == "text" {
		out.RawEncoding = ""
	}
	out.Warnings = appendNew(nil, warnings...)
	return out, nil
}

func appendNew(dst []string, src ...string) []string {
	for _, s := range src {
		dup := false
		for _, x := range dst {
			if x == s {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, s)
		}
	}
	return dst
}

func wsSecurity(a *auth.Config) (*soap.WSSecurity, error) {
	if a == nil || a.Kind() != "ws_security" {
		return nil, nil
	}
	w := &soap.WSSecurity{Username: a.Username, Password: a.Password}
	if w.Username == "" {
		return nil, errors.New("auth ws_security: username is required")
	}
	if c := a.WSSec; c != nil {
		digest, err := soap.ParsePasswordType(c.PasswordType)
		if err != nil {
			return nil, err
		}
		w.Digest = digest
		w.Timestamp = c.Timestamp
		w.MustUnderstand = c.MustUnderstand
		if c.TTLSeconds > 0 {
			w.TTL = time.Duration(c.TTLSeconds * float64(time.Second))
		}
	}
	return w, nil
}
