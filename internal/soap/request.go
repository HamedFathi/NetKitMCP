package soap

import (
	"errors"
	"fmt"
	"strings"
)

// PrepareOptions describe a SOAP call to build.
type PrepareOptions struct {
	Defs       *Definitions // may be nil for raw bodies
	Operation  string
	Service    string
	Port       string
	Args       any
	RawBody    string
	Version    string  // "", "1.1" or "1.2"
	SOAPAction *string // override
	// Headers returns raw header blocks (already validated, e.g. a
	// wsse:Security block) once the SOAP version is known. May be nil.
	Headers func(version string) ([]string, error)
}

// Prepared is a ready-to-send SOAP request.
type Prepared struct {
	Op          *OpBinding // nil for raw calls without an operation
	Version     string
	Action      string
	Envelope    string
	ContentType string
	Warnings    []string
}

// Prepare builds the envelope and HTTP metadata for a call.
func Prepare(o PrepareOptions) (*Prepared, error) {
	p := &Prepared{}
	if o.Operation != "" {
		if o.Defs == nil {
			return nil, errors.New("operation requires a WSDL (wsdl_url, wsdl_file or wsdl)")
		}
		op, err := o.Defs.FindOperation(o.Operation, o.Service, o.Port, o.Version)
		if err != nil {
			return nil, err
		}
		p.Op = op
	}
	p.Version = o.Version
	if p.Op != nil {
		if p.Version == "" {
			p.Version = p.Op.Binding.SOAPVersion
		} else if p.Version != p.Op.Binding.SOAPVersion {
			p.Warnings = append(p.Warnings, fmt.Sprintf("binding %s is SOAP %s but soap_version %s was requested", p.Op.Binding.Name.Local, p.Op.Binding.SOAPVersion, p.Version))
		}
		p.Action = p.Op.BOp.SOAPAction
		if p.Op.BOp.MIME {
			p.Warnings = append(p.Warnings, "this operation uses MIME/MTOM attachments, which are not supported; the request is sent as a plain SOAP envelope")
		}
	}
	if o.SOAPAction != nil {
		p.Action = *o.SOAPAction
	}

	headers := func(version string) ([]string, error) {
		if o.Headers == nil {
			return nil, nil
		}
		return o.Headers(version)
	}

	switch {
	case strings.TrimSpace(o.RawBody) != "":
		if o.Args != nil {
			return nil, errors.New("set either args or raw_body, not both")
		}
		raw := strings.TrimSpace(o.RawBody)
		_, rawVer, isEnv, err := RawEnvelope(raw, nil)
		if err != nil {
			return nil, err
		}
		if isEnv {
			if o.Version != "" && o.Version != rawVer {
				p.Warnings = append(p.Warnings, fmt.Sprintf("raw_body is a SOAP %s envelope; soap_version %s ignored", rawVer, o.Version))
			}
			p.Version = rawVer
			hs, err := headers(p.Version)
			if err != nil {
				return nil, err
			}
			if p.Envelope, _, _, err = RawEnvelope(raw, hs); err != nil {
				return nil, err
			}
		} else {
			if err := CheckFragment(raw); err != nil {
				return nil, fmt.Errorf("raw_body is not well-formed XML: %w", err)
			}
			if p.Version == "" {
				p.Version = "1.1"
			}
			hs, err := headers(p.Version)
			if err != nil {
				return nil, err
			}
			p.Envelope = Envelope(p.Version, hs, raw)
		}
	case p.Op != nil:
		if p.Version == "" {
			p.Version = "1.1"
		}
		bs := o.Defs.Body(p.Op, false)
		rpc := p.Op.Style() == "rpc"
		b := &Builder{EnvNS: EnvNS(p.Version), Encoded: bs.Use == "encoded"}
		if b.Encoded {
			p.Warnings = append(p.Warnings, "SOAP encoding (use=encoded) is supported on a best-effort basis (xsi:type on simple values, no multi-references)")
		}
		elems, err := b.BuildBody(bs, rpc, o.Args)
		if err != nil {
			return nil, err
		}
		p.Warnings = append(p.Warnings, b.Warnings...)
		hs, err := headers(p.Version)
		if err != nil {
			return nil, err
		}
		p.Envelope = Envelope(p.Version, hs, SerializeBody(elems, p.Version))
	default:
		return nil, errors.New("set operation (with a WSDL and args) or raw_body")
	}
	if p.Version == "1.2" {
		p.ContentType = "application/soap+xml; charset=utf-8"
		if p.Action != "" {
			p.ContentType += "; action=" + quoteString(p.Action)
		}
	} else {
		p.ContentType = "text/xml; charset=utf-8"
	}
	return p, nil
}

// SOAPActionHeader returns the SOAP 1.1 SOAPAction header value (quoted),
// or "" for SOAP 1.2.
func (p *Prepared) SOAPActionHeader() string {
	if p.Version == "1.2" {
		return ""
	}
	return quoteString(p.Action)
}

// quoteString renders an RFC 7230 quoted-string (backslash-escaping '"'
// and '\'), so an action URI cannot break out of the header parameter.
func quoteString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
