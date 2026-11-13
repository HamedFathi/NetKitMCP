package soap

import (
	"fmt"
	"sort"
	"strings"
)

// OpBinding is a concrete operation: an abstract operation bound by a SOAP
// binding and (usually) exposed by a service port.
type OpBinding struct {
	Service  string
	Port     string
	Address  string
	Binding  *Binding
	BOp      *BindingOperation
	PortType *PortType
	Op       *Operation
}

// Style returns the effective style (document or rpc).
func (o *OpBinding) Style() string {
	if o.BOp.Style != "" {
		return o.BOp.Style
	}
	if o.Binding.Style != "" {
		return o.Binding.Style
	}
	return "document"
}

const unboundService = "(no service)"

// Concrete lists every concrete operation in document order.
func (d *Definitions) Concrete() []*OpBinding {
	var out []*OpBinding
	used := map[*Binding]bool{}
	add := func(svc string, p *Port, b *Binding) {
		used[b] = true
		pt := d.lookupPortType(b.PortType)
		for _, bo := range b.Operations {
			ob := &OpBinding{Service: svc, Binding: b, BOp: bo, PortType: pt}
			if p != nil {
				ob.Port, ob.Address = p.Name, p.Address
			}
			if pt != nil {
				for _, op := range pt.Operations {
					if op.Name == bo.Name {
						ob.Op = op
						break
					}
				}
			}
			if ob.Op == nil {
				ob.Op = &Operation{Name: bo.Name}
			}
			out = append(out, ob)
		}
	}
	for _, s := range d.Services {
		for _, p := range s.Ports {
			if b := d.lookupBinding(p.Binding); b != nil {
				add(s.Name, p, b)
			}
		}
	}
	for _, q := range d.bindingOrder {
		if b := d.Bindings[q]; !used[b] {
			add(unboundService, nil, b)
		}
	}
	return out
}

// FindOperation selects a concrete operation by name, optionally filtered
// by service, port and SOAP version (a preference, not a filter).
func (d *Definitions) FindOperation(name, service, port, version string) (*OpBinding, error) {
	all := d.Concrete()
	if len(all) == 0 {
		return nil, fmt.Errorf("the WSDL has no SOAP bindings")
	}
	match := func(eq func(a, b string) bool) []*OpBinding {
		var out []*OpBinding
		for _, o := range all {
			if !eq(o.BOp.Name, name) {
				continue
			}
			if service != "" && !strings.EqualFold(o.Service, service) {
				continue
			}
			if port != "" && !strings.EqualFold(o.Port, port) {
				continue
			}
			out = append(out, o)
		}
		return out
	}
	cands := match(func(a, b string) bool { return a == b })
	if len(cands) == 0 {
		cands = match(strings.EqualFold)
	}
	if len(cands) == 0 {
		names := map[string]bool{}
		for _, o := range all {
			names[o.BOp.Name] = true
		}
		list := make([]string, 0, len(names))
		for n := range names {
			list = append(list, n)
		}
		sort.Strings(list)
		where := ""
		if service != "" || port != "" {
			where = fmt.Sprintf(" (service %q, port %q)", service, port)
		}
		return nil, fmt.Errorf("operation %q not found%s; available operations: %s", name, where, strings.Join(list, ", "))
	}
	if version != "" {
		for _, o := range cands {
			if o.Binding.SOAPVersion == version {
				return o, nil
			}
		}
	}
	return cands[0], nil
}

// PartDesc describes a message part.
type PartDesc struct {
	Name    string `json:"name"`
	Element string `json:"element,omitempty"`
	Type    string `json:"type,omitempty"`
}

// BodyShape describes the body of an input or output message.
type BodyShape struct {
	Message     QName
	Use         string
	Namespace   string // rpc wrapper namespace
	Parts       []PartDesc
	HeaderParts []PartDesc
	Fields      []*Field // body children in order
	Wrapped     bool     // document/literal wrapped convention
}

// Body resolves the input (output=false) or output body of a concrete operation.
func (d *Definitions) Body(o *OpBinding, output bool) *BodyShape {
	msgName := o.Op.Input
	bb := o.BOp.Input
	if output {
		msgName, bb = o.Op.Output, o.BOp.Output
	}
	bs := &BodyShape{Message: msgName, Use: bb.Use}
	if msgName.IsZero() {
		return bs
	}
	msg := d.lookupMessage(msgName)
	if msg == nil {
		d.Schemas.warn("message %s not found", msgName)
		return bs
	}
	headerParts := map[string]bool{}
	for _, h := range bb.Headers {
		hm := d.lookupMessage(h.Message)
		if hm == nil {
			continue
		}
		for _, p := range hm.Parts {
			if p.Name == h.Part {
				bs.HeaderParts = append(bs.HeaderParts, partDesc(p))
				if hm == msg {
					headerParts[p.Name] = true
				}
			}
		}
	}
	var parts []*Part
	if bb.Parts != nil {
		for _, pn := range bb.Parts {
			for _, p := range msg.Parts {
				if p.Name == pn {
					parts = append(parts, p)
				}
			}
		}
	} else {
		for _, p := range msg.Parts {
			if !headerParts[p.Name] {
				parts = append(parts, p)
			}
		}
	}
	for _, p := range parts {
		bs.Parts = append(bs.Parts, partDesc(p))
	}
	if o.Style() == "rpc" {
		ns := bb.Namespace
		if ns == "" {
			ns = d.TargetNS
			d.Schemas.warn("rpc operation %s has no soap:body namespace; using the target namespace", o.BOp.Name)
		}
		bs.Namespace = ns
		name := o.BOp.Name
		if output {
			name += "Response"
		}
		w := &Field{Kind: KindElement, Name: name, NS: ns, Min: 1, Max: 1}
		for _, p := range parts {
			w.Children = append(w.Children, d.partField(p, true))
		}
		bs.Fields = []*Field{w}
		return bs
	}
	for _, p := range parts {
		bs.Fields = append(bs.Fields, d.partField(p, false))
	}
	if !output && len(parts) == 1 && !parts[0].Element.IsZero() && parts[0].Element.Local == o.BOp.Name {
		bs.Wrapped = true
	}
	return bs
}

func (d *Definitions) partField(p *Part, rpc bool) *Field {
	if !p.Element.IsZero() {
		if f, ok := d.Schemas.Element(p.Element); ok {
			return f
		}
		d.Schemas.warn("element %s of part %s not found", p.Element, p.Name)
		return &Field{Kind: KindElement, Name: p.Element.Local, NS: p.Element.Space, Min: 1, Max: 1, Simple: &SimpleInfo{Base: "anyType"}}
	}
	if !p.Type.IsZero() {
		return d.Schemas.TypeField(p.Name, "", p.Type)
	}
	return &Field{Kind: KindElement, Name: p.Name, Min: 1, Max: 1, Simple: &SimpleInfo{Base: "anyType"}}
}

func partDesc(p *Part) PartDesc {
	pd := PartDesc{Name: p.Name}
	if !p.Element.IsZero() {
		pd.Element = p.Element.String()
	}
	if !p.Type.IsZero() {
		pd.Type = p.Type.String()
	}
	return pd
}

// Description is the soap_describe result.
type Description struct {
	Name            string           `json:"name,omitempty"`
	TargetNamespace string           `json:"target_namespace"`
	Documents       []string         `json:"documents"`
	Services        []ServiceDesc    `json:"services"`
	Operations      *OMap            `json:"operations,omitempty"`
	Operation       *OperationDetail `json:"operation,omitempty"`
	Warnings        []string         `json:"warnings,omitempty"`
}

// ServiceDesc describes a service.
type ServiceDesc struct {
	Name          string     `json:"name"`
	Documentation string     `json:"documentation,omitempty"`
	Ports         []PortDesc `json:"ports"`
}

// PortDesc describes a port and its binding.
type PortDesc struct {
	Name        string      `json:"name,omitempty"`
	Binding     string      `json:"binding"`
	SOAPVersion string      `json:"soap_version"`
	Style       string      `json:"style"`
	Transport   string      `json:"transport,omitempty"`
	Address     string      `json:"address,omitempty"`
	Operations  []OpSummary `json:"operations"`
}

// OpSummary is a one-line operation summary within a port.
type OpSummary struct {
	Name       string `json:"name"`
	SOAPAction string `json:"soap_action"`
	Style      string `json:"style"`
	InputUse   string `json:"input_use"`
	OutputUse  string `json:"output_use,omitempty"`
	OneWay     bool   `json:"one_way,omitempty"`
}

// OperationShape gives the input/output skeletons of an operation.
type OperationShape struct {
	Documentation string   `json:"documentation,omitempty"`
	Input         any      `json:"input"`
	Output        any      `json:"output,omitempty"`
	Faults        []string `json:"faults,omitempty"`
}

// OperationDetail is the detailed view of one operation.
type OperationDetail struct {
	Name          string         `json:"name"`
	Documentation string         `json:"documentation,omitempty"`
	Service       string         `json:"service,omitempty"`
	Port          string         `json:"port,omitempty"`
	Endpoint      string         `json:"endpoint,omitempty"`
	SOAPVersion   string         `json:"soap_version"`
	SOAPAction    string         `json:"soap_action"`
	Style         string         `json:"style"`
	Wrapped       bool           `json:"wrapped,omitempty"`
	OtherPorts    []string       `json:"other_ports,omitempty"`
	Input         *MessageDetail `json:"input"`
	Output        *MessageDetail `json:"output,omitempty"`
	Faults        []FaultDetail  `json:"faults,omitempty"`
	ArgsHint      string         `json:"args_hint"`
}

// MessageDetail describes one message in detail.
type MessageDetail struct {
	Message   string     `json:"message"`
	Use       string     `json:"use"`
	Namespace string     `json:"namespace,omitempty"`
	Parts     []PartDesc `json:"parts"`
	Headers   []PartDesc `json:"header_parts,omitempty"`
	Shape     any        `json:"shape"`
}

// FaultDetail describes a declared fault.
type FaultDetail struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

// maxShapeOps bounds how many operation shapes the overview renders.
const maxShapeOps = 40

// Describe builds the soap_describe view. With operation set, it details
// that operation (service/port narrow the choice).
func (d *Definitions) Describe(operation, service, port string) (*Description, error) {
	desc := &Description{Name: d.Name, TargetNamespace: d.TargetNS, Documents: d.Documents}
	all := d.Concrete()
	byPort := map[string]*PortDesc{}
	var portOrder []string
	svcDocs := map[string]string{}
	for _, s := range d.Services {
		svcDocs[s.Name] = s.Documentation
	}
	for _, o := range all {
		key := o.Service + "\x00" + o.Port + "\x00" + o.Binding.Name.String()
		pd := byPort[key]
		if pd == nil {
			pd = &PortDesc{
				Name: o.Port, Binding: o.Binding.Name.Local, SOAPVersion: o.Binding.SOAPVersion,
				Style: o.Binding.Style, Transport: o.Binding.Transport, Address: o.Address,
				Operations: []OpSummary{},
			}
			byPort[key] = pd
			portOrder = append(portOrder, key)
		}
		pd.Operations = append(pd.Operations, OpSummary{
			Name: o.BOp.Name, SOAPAction: o.BOp.SOAPAction, Style: o.Style(),
			InputUse: o.BOp.Input.Use, OutputUse: outputUse(o), OneWay: o.Op.Output.IsZero(),
		})
	}
	svcIdx := map[string]int{}
	for _, key := range portOrder {
		svc := strings.SplitN(key, "\x00", 2)[0]
		i, ok := svcIdx[svc]
		if !ok {
			i = len(desc.Services)
			svcIdx[svc] = i
			desc.Services = append(desc.Services, ServiceDesc{Name: svc, Documentation: svcDocs[svc]})
		}
		desc.Services[i].Ports = append(desc.Services[i].Ports, *byPort[key])
	}
	if desc.Services == nil {
		desc.Services = []ServiceDesc{}
	}

	if operation != "" {
		o, err := d.FindOperation(operation, service, port, "")
		if err != nil {
			return nil, err
		}
		desc.Operation = d.detail(o, all)
		desc.Warnings = d.AllWarnings()
		return desc, nil
	}

	// One shape entry per abstract operation (first binding wins).
	seen := map[string]bool{}
	var firsts []*OpBinding
	for _, o := range all {
		k := o.BOp.Name
		if o.PortType != nil {
			k = o.PortType.Name.String() + "#" + o.BOp.Name
		}
		if !seen[k] {
			seen[k] = true
			firsts = append(firsts, o)
		}
	}
	if len(firsts) > maxShapeOps {
		desc.Warnings = append(desc.Warnings, fmt.Sprintf("%d operations: shapes omitted; call soap_describe with operation=<name> for one operation", len(firsts)))
	} else {
		ops := NewOMap()
		names := map[string]int{}
		for _, o := range firsts {
			names[o.BOp.Name]++
		}
		for _, o := range firsts {
			key := o.BOp.Name
			if names[key] > 1 && o.PortType != nil {
				key = o.PortType.Name.Local + "." + key
			}
			sh := OperationShape{Documentation: o.Op.Documentation}
			in := d.Body(o, false)
			sh.Input = Skeletons(in.Fields)
			if !o.Op.Output.IsZero() {
				sh.Output = Skeletons(d.Body(o, true).Fields)
			}
			for _, f := range o.Op.Faults {
				sh.Faults = append(sh.Faults, f.Name)
			}
			ops.Set(key, sh)
		}
		desc.Operations = ops
	}
	desc.Warnings = append(desc.Warnings, d.AllWarnings()...)
	return desc, nil
}

func outputUse(o *OpBinding) string {
	if o.Op.Output.IsZero() {
		return ""
	}
	return o.BOp.Output.Use
}

func (d *Definitions) detail(o *OpBinding, all []*OpBinding) *OperationDetail {
	od := &OperationDetail{
		Name: o.BOp.Name, Documentation: o.Op.Documentation, Service: o.Service, Port: o.Port,
		Endpoint: o.Address, SOAPVersion: o.Binding.SOAPVersion, SOAPAction: o.BOp.SOAPAction, Style: o.Style(),
	}
	if od.Service == unboundService {
		od.Service = ""
	}
	for _, x := range all {
		// o comes from a separate Concrete() call, so compare by identity
		// of (service, port, binding operation) rather than by pointer.
		same := x.Service == o.Service && x.Port == o.Port && x.BOp == o.BOp
		if !same && x.BOp.Name == o.BOp.Name {
			od.OtherPorts = append(od.OtherPorts, fmt.Sprintf("%s/%s (SOAP %s)", x.Service, x.Port, x.Binding.SOAPVersion))
		}
	}
	in := d.Body(o, false)
	od.Wrapped = in.Wrapped
	od.Input = messageDetail(in)
	if !o.Op.Output.IsZero() {
		od.Output = messageDetail(d.Body(o, true))
	}
	for _, f := range o.Op.Faults {
		fd := FaultDetail{Name: f.Name, Message: f.Message.String()}
		if m := d.lookupMessage(f.Message); m != nil {
			var fields []*Field
			for _, p := range m.Parts {
				fields = append(fields, d.partField(p, false))
			}
			fd.Detail = Skeletons(fields)
		}
		od.Faults = append(od.Faults, fd)
	}
	switch {
	case o.Style() == "rpc":
		od.ArgsHint = "args: an object keyed by part name (the " + o.BOp.Name + " wrapper element is added automatically); the input shape shows the full body"
	case len(in.Fields) == 1:
		od.ArgsHint = "args: the content of " + in.Fields[0].Name + " (or the whole input shape); keys ending in '?' are optional, '@x' are attributes"
	default:
		od.ArgsHint = "args: an object keyed by body element name, as in the input shape"
	}
	return od
}

func messageDetail(bs *BodyShape) *MessageDetail {
	md := &MessageDetail{
		Message: bs.Message.String(), Use: bs.Use, Namespace: bs.Namespace,
		Parts: bs.Parts, Headers: bs.HeaderParts, Shape: Skeletons(bs.Fields),
	}
	if md.Parts == nil {
		md.Parts = []PartDesc{}
	}
	return md
}
