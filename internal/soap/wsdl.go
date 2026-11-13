package soap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Location identifies a WSDL/XSD document: a URL or a file path. Both empty
// means an inline document (relative imports cannot be resolved).
type Location struct {
	URL  string
	File string
}

// String returns the URL or path.
func (l Location) String() string {
	switch {
	case l.URL != "":
		return l.URL
	case l.File != "":
		return l.File
	}
	return "(inline)"
}

// Fetcher retrieves documents referenced by imports. Implementations must
// apply the SSRF guard (URLs) and the file policy (files).
type Fetcher interface {
	Fetch(ctx context.Context, loc Location) ([]byte, error)
}

// FetchFunc adapts a function to Fetcher.
type FetchFunc func(ctx context.Context, loc Location) ([]byte, error)

// Fetch calls f.
func (f FetchFunc) Fetch(ctx context.Context, loc Location) ([]byte, error) { return f(ctx, loc) }

// LoadOptions bound import resolution.
type LoadOptions struct {
	MaxDepth int // nesting depth of imports (default 8)
	MaxDocs  int // total documents loaded including the root (default 32)
}

// Definitions is a parsed WSDL 1.1 document set.
type Definitions struct {
	Name      string
	TargetNS  string
	Messages  map[QName]*Message
	PortTypes map[QName]*PortType
	Bindings  map[QName]*Binding
	Services  []*Service
	Schemas   *SchemaSet
	Documents []string // locations loaded, root first
	Warnings  []string

	portTypeOrder []QName
	bindingOrder  []QName
	usesMTOM      bool
}

// Message is a wsdl:message.
type Message struct {
	Name  QName
	Parts []*Part
}

// Part is a message part (element= or type=).
type Part struct {
	Name    string
	Element QName
	Type    QName
}

// PortType is a wsdl:portType.
type PortType struct {
	Name       QName
	Operations []*Operation
}

// Operation is an abstract operation of a portType.
type Operation struct {
	Name          string
	Documentation string
	Input         QName // message
	Output        QName // message (zero for one-way)
	Faults        []FaultRef
}

// FaultRef names a declared fault message.
type FaultRef struct {
	Name    string
	Message QName
}

// Binding is a SOAP binding of a portType.
type Binding struct {
	Name        QName
	PortType    QName
	SOAPVersion string // "1.1" or "1.2"
	Style       string // default style (document or rpc)
	Transport   string
	Operations  []*BindingOperation
}

// BindingOperation is the SOAP binding of one operation.
type BindingOperation struct {
	Name       string
	SOAPAction string
	Style      string
	Input      BodyBinding
	Output     BodyBinding
	MIME       bool // uses mime:multipartRelated (attachments)
}

// BodyBinding is the soap:body (and soap:header) binding of a message.
type BodyBinding struct {
	Use           string   // literal or encoded
	Namespace     string   // rpc wrapper namespace
	EncodingStyle string   // for encoded
	Parts         []string // soap:body parts="..." restriction (nil = all)
	Headers       []HeaderBinding
}

// HeaderBinding is a soap:header element of an input or output.
type HeaderBinding struct {
	Message QName
	Part    string
	Use     string
}

// Service is a wsdl:service.
type Service struct {
	Name          string
	Documentation string
	Ports         []*Port
}

// Port is a wsdl:port with a SOAP address.
type Port struct {
	Name    string
	Binding QName
	Address string
}

// Load parses a WSDL 1.1 document (or a bare XSD) and resolves wsdl:import,
// xs:import and xs:include through fetch, relative to base.
func Load(ctx context.Context, data []byte, base Location, fetch Fetcher, opts LoadOptions) (*Definitions, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 8
	}
	if opts.MaxDocs <= 0 {
		opts.MaxDocs = 32
	}
	l := &loader{
		ctx:   ctx,
		fetch: fetch,
		opts:  opts,
		seen:  map[string]bool{},
		defs: &Definitions{
			Messages:  map[QName]*Message{},
			PortTypes: map[QName]*PortType{},
			Bindings:  map[QName]*Binding{},
			Schemas:   newSchemaSet(),
		},
	}
	if base.URL != "" || base.File != "" {
		l.seen[base.String()] = true
	}
	l.defs.Documents = append(l.defs.Documents, base.String())
	root, err := ParseXML(data)
	if err != nil {
		return nil, fmt.Errorf("parsing WSDL %s: %w", base, err)
	}
	switch {
	case root.Is(NSWSDL20, "description"):
		return nil, errors.New("WSDL 2.0 is not supported (only WSDL 1.1); send a raw_body with soap_request instead")
	case root.Is(NSWSDL, "definitions"):
		l.defs.Name = root.Attr("name")
		l.defs.TargetNS = root.Attr("targetNamespace")
		if err := l.wsdl(root, base, 0); err != nil {
			return nil, err
		}
	case isXSDNS(root.Name.Space) && root.Name.Local == "schema":
		l.schema(root, base, 0, "")
		l.warn("document is an XML Schema, not a WSDL: only types are available")
	default:
		return nil, fmt.Errorf("%s is not a WSDL 1.1 document (root element is {%s}%s)", base, root.Name.Space, root.Name.Local)
	}
	if l.defs.usesMTOM {
		l.warn("the WSDL declares MTOM/XOP or MIME attachments, which are not supported; use raw_body for inline (base64) content only")
	}
	return l.defs, nil
}

type loader struct {
	ctx   context.Context
	fetch Fetcher
	opts  LoadOptions
	seen  map[string]bool
	defs  *Definitions
}

func (l *loader) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	for _, w := range l.defs.Warnings {
		if w == msg {
			return
		}
	}
	l.defs.Warnings = append(l.defs.Warnings, msg)
}

// load fetches and parses an imported document. It returns nil when the
// document was already loaded or could not be loaded (a warning is added).
func (l *loader) load(base Location, ref string, depth int) (*Node, Location) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, Location{}
	}
	loc, err := ResolveLocation(base, ref)
	if err != nil {
		l.warn("import %q skipped: %v", ref, err)
		return nil, Location{}
	}
	key := loc.String()
	if l.seen[key] {
		return nil, Location{}
	}
	l.seen[key] = true
	if depth > l.opts.MaxDepth {
		l.warn("import %s skipped: import depth limit (%d) reached", key, l.opts.MaxDepth)
		return nil, Location{}
	}
	if len(l.defs.Documents) >= l.opts.MaxDocs {
		l.warn("import %s skipped: document limit (%d) reached", key, l.opts.MaxDocs)
		return nil, Location{}
	}
	if l.fetch == nil {
		l.warn("import %s skipped: no fetcher", key)
		return nil, Location{}
	}
	data, err := l.fetch.Fetch(l.ctx, loc)
	if err != nil {
		l.warn("import %s failed: %v", key, err)
		return nil, Location{}
	}
	l.defs.Documents = append(l.defs.Documents, key)
	n, err := ParseXML(data)
	if err != nil {
		l.warn("import %s: %v", key, err)
		return nil, Location{}
	}
	return n, loc
}

// ResolveLocation resolves an import location against its base. Documents
// loaded from a URL may only import URLs (never local files).
func ResolveLocation(base Location, ref string) (Location, error) {
	if base.File != "" && (filepath.IsAbs(ref) || filepath.VolumeName(ref) != "") {
		return Location{File: filepath.Clean(ref)}, nil
	}
	u, err := url.Parse(ref)
	if err != nil {
		return Location{}, fmt.Errorf("invalid location: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return Location{URL: u.String()}, nil
	case "":
	default:
		return Location{}, fmt.Errorf("unsupported scheme %q (only http, https and relative paths are allowed)", u.Scheme)
	}
	switch {
	case base.URL != "":
		bu, err := url.Parse(base.URL)
		if err != nil {
			return Location{}, err
		}
		return Location{URL: bu.ResolveReference(u).String()}, nil
	case base.File != "":
		p, err := url.PathUnescape(u.Path)
		if err != nil {
			p = u.Path
		}
		if p == "" {
			return Location{}, errors.New("empty path")
		}
		return Location{File: filepath.Join(filepath.Dir(base.File), filepath.FromSlash(p))}, nil
	default:
		return Location{}, errors.New("relative locations cannot be resolved for an inline WSDL; use wsdl_url or wsdl_file")
	}
}

func (l *loader) wsdl(root *Node, base Location, depth int) error {
	tns := root.Attr("targetNamespace")
	for _, c := range root.Children {
		if c.Name.Space != NSWSDL {
			if c.Name.Local == "Policy" || c.Name.Local == "PolicyReference" {
				l.scanPolicy(c)
			}
			continue
		}
		switch c.Name.Local {
		case "import":
			n, loc := l.load(base, c.Attr("location"), depth+1)
			if n == nil {
				continue
			}
			switch {
			case n.Is(NSWSDL, "definitions"):
				if err := l.wsdl(n, loc, depth+1); err != nil {
					return err
				}
			case isXSDNS(n.Name.Space) && n.Name.Local == "schema":
				l.schema(n, loc, depth+1, "")
			case n.Is(NSWSDL20, "description"):
				l.warn("import %s is WSDL 2.0 (not supported)", loc)
			default:
				l.warn("import %s: unexpected root element %s", loc, n.Name.Local)
			}
		case "types":
			for _, s := range c.Children {
				if isXSDNS(s.Name.Space) && s.Name.Local == "schema" {
					l.schema(s, base, depth, "")
				}
			}
		case "message":
			m := &Message{Name: QName{Space: tns, Local: c.Attr("name")}}
			for _, p := range c.ChildrenNamed(NSWSDL, "part") {
				part := &Part{Name: p.Attr("name")}
				if v := p.Attr("element"); v != "" {
					part.Element = p.ResolveQName(v)
				}
				if v := p.Attr("type"); v != "" {
					part.Type = p.ResolveQName(v)
				}
				m.Parts = append(m.Parts, part)
			}
			l.defs.Messages[m.Name] = m
		case "portType":
			pt := &PortType{Name: QName{Space: tns, Local: c.Attr("name")}}
			for _, o := range c.ChildrenNamed(NSWSDL, "operation") {
				op := &Operation{Name: o.Attr("name"), Documentation: docText(o)}
				if in := o.Child(NSWSDL, "input"); in != nil {
					op.Input = in.ResolveQName(in.Attr("message"))
				}
				if out := o.Child(NSWSDL, "output"); out != nil {
					op.Output = out.ResolveQName(out.Attr("message"))
				}
				for _, f := range o.ChildrenNamed(NSWSDL, "fault") {
					op.Faults = append(op.Faults, FaultRef{Name: f.Attr("name"), Message: f.ResolveQName(f.Attr("message"))})
				}
				pt.Operations = append(pt.Operations, op)
			}
			if _, dup := l.defs.PortTypes[pt.Name]; !dup {
				l.defs.portTypeOrder = append(l.defs.portTypeOrder, pt.Name)
			}
			l.defs.PortTypes[pt.Name] = pt
		case "binding":
			b := l.binding(c, tns)
			if b == nil {
				continue
			}
			if _, dup := l.defs.Bindings[b.Name]; !dup {
				l.defs.bindingOrder = append(l.defs.bindingOrder, b.Name)
			}
			l.defs.Bindings[b.Name] = b
		case "service":
			svc := &Service{Name: c.Attr("name"), Documentation: docText(c)}
			for _, p := range c.ChildrenNamed(NSWSDL, "port") {
				port := &Port{Name: p.Attr("name"), Binding: p.ResolveQName(p.Attr("binding"))}
				for _, a := range p.Children {
					if a.Name.Local == "address" && (a.Name.Space == NSWSDLSOAP11 || a.Name.Space == NSWSDLSOAP12) {
						port.Address = a.Attr("location")
					}
				}
				svc.Ports = append(svc.Ports, port)
			}
			l.defs.Services = append(l.defs.Services, svc)
		}
	}
	return nil
}

func (l *loader) scanPolicy(n *Node) {
	if n.Name.Local == "OptimizedMimeSerialization" || n.Name.Local == "MTOM" {
		l.defs.usesMTOM = true
		return
	}
	for _, c := range n.Children {
		l.scanPolicy(c)
	}
}

func docText(n *Node) string {
	if d := n.Child(NSWSDL, "documentation"); d != nil {
		return strings.Join(strings.Fields(d.Text), " ")
	}
	return ""
}

func (l *loader) binding(c *Node, tns string) *Binding {
	b := &Binding{Name: QName{Space: tns, Local: c.Attr("name")}, PortType: c.ResolveQName(c.Attr("type"))}
	soapNS := ""
	for _, ch := range c.Children {
		if ch.Name.Local == "binding" && (ch.Name.Space == NSWSDLSOAP11 || ch.Name.Space == NSWSDLSOAP12) {
			soapNS = ch.Name.Space
			b.Style = ch.Attr("style")
			b.Transport = ch.Attr("transport")
		}
		if ch.Name.Local == "Policy" || ch.Name.Local == "PolicyReference" {
			l.scanPolicy(ch)
		}
	}
	if soapNS == "" {
		if c.Child(NSWSDLHTTP, "binding") != nil {
			l.warn("binding %s is an HTTP (non-SOAP) binding and was skipped", b.Name.Local)
		} else {
			l.warn("binding %s has no SOAP binding element and was skipped", b.Name.Local)
		}
		return nil
	}
	b.SOAPVersion = "1.1"
	if soapNS == NSWSDLSOAP12 {
		b.SOAPVersion = "1.2"
	}
	if b.Style == "" {
		b.Style = "document"
	}
	for _, o := range c.ChildrenNamed(NSWSDL, "operation") {
		bo := &BindingOperation{Name: o.Attr("name")}
		if so := o.Child(soapNS, "operation"); so != nil {
			bo.SOAPAction = so.Attr("soapAction")
			bo.Style = so.Attr("style")
		}
		if bo.Style == "" {
			bo.Style = b.Style
		}
		if in := o.Child(NSWSDL, "input"); in != nil {
			bo.Input = bodyBinding(in, soapNS, &bo.MIME)
		}
		if out := o.Child(NSWSDL, "output"); out != nil {
			bo.Output = bodyBinding(out, soapNS, &bo.MIME)
		}
		if bo.MIME {
			l.defs.usesMTOM = true
		}
		for _, ch := range o.Children {
			if ch.Name.Local == "Policy" || ch.Name.Local == "PolicyReference" {
				l.scanPolicy(ch)
			}
		}
		b.Operations = append(b.Operations, bo)
	}
	return b
}

func bodyBinding(n *Node, soapNS string, mime *bool) BodyBinding {
	var bb BodyBinding
	var visit func(n *Node)
	visit = func(n *Node) {
		for _, c := range n.Children {
			switch {
			case c.Is(soapNS, "body"):
				bb.Use = c.Attr("use")
				bb.Namespace = c.Attr("namespace")
				bb.EncodingStyle = c.Attr("encodingStyle")
				if c.HasAttr("parts") {
					bb.Parts = strings.Fields(c.Attr("parts"))
					if bb.Parts == nil {
						bb.Parts = []string{}
					}
				}
			case c.Is(soapNS, "header"):
				bb.Headers = append(bb.Headers, HeaderBinding{
					Message: c.ResolveQName(c.Attr("message")),
					Part:    c.Attr("part"),
					Use:     c.Attr("use"),
				})
			case c.Name.Space == NSWSDLMIME:
				if c.Name.Local == "multipartRelated" {
					*mime = true
				}
				visit(c)
			}
		}
	}
	visit(n)
	if bb.Use == "" {
		bb.Use = "literal"
	}
	return bb
}

func (l *loader) schema(n *Node, base Location, depth int, tnsOverride string) {
	sd := l.defs.Schemas.add(n, tnsOverride)
	for _, c := range n.Children {
		if !isXSDNS(c.Name.Space) {
			continue
		}
		switch c.Name.Local {
		case "import":
			loc := c.Attr("schemaLocation")
			if loc == "" {
				continue // namespace provided by another schema in the set
			}
			if s, sl := l.load(base, loc, depth+1); s != nil {
				if isXSDNS(s.Name.Space) && s.Name.Local == "schema" {
					l.schema(s, sl, depth+1, "")
				} else {
					l.warn("xs:import %s is not an XML Schema", sl)
				}
			}
		case "include", "redefine":
			if s, sl := l.load(base, c.Attr("schemaLocation"), depth+1); s != nil {
				if isXSDNS(s.Name.Space) && s.Name.Local == "schema" {
					l.schema(s, sl, depth+1, sd.tns)
				} else {
					l.warn("xs:%s %s is not an XML Schema", c.Name.Local, sl)
				}
			}
		}
	}
}

// lookupMessage finds a message by QName with a local-name fallback.
func (d *Definitions) lookupMessage(q QName) *Message {
	if m, ok := d.Messages[q]; ok {
		return m
	}
	var found *Message
	n := 0
	for k, m := range d.Messages {
		if k.Local == q.Local {
			found = m
			n++
		}
	}
	if n == 1 {
		return found
	}
	return nil
}

func (d *Definitions) lookupPortType(q QName) *PortType {
	if p, ok := d.PortTypes[q]; ok {
		return p
	}
	for _, k := range d.portTypeOrder {
		if k.Local == q.Local {
			return d.PortTypes[k]
		}
	}
	return nil
}

func (d *Definitions) lookupBinding(q QName) *Binding {
	if b, ok := d.Bindings[q]; ok {
		return b
	}
	for _, k := range d.bindingOrder {
		if k.Local == q.Local {
			return d.Bindings[k]
		}
	}
	return nil
}

// AllWarnings returns loader and schema warnings.
func (d *Definitions) AllWarnings() []string {
	out := append([]string(nil), d.Warnings...)
	return append(out, d.Schemas.Warnings...)
}
