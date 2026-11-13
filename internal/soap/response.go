package soap

import (
	"fmt"
	"strconv"
	"strings"
)

// XML-to-JSON conventions:
//   - element names without prefixes are keys
//   - attributes become "@name" (xmlns and xsi:* attributes are dropped)
//   - repeated elements become arrays (also single ones when the schema
//     says maxOccurs > 1)
//   - text-only elements become strings (typed as number/boolean when the
//     schema says so); text next to attributes or child elements is "#text"
//   - xsi:nil="true" becomes null; empty elements become ""

// ToJSON converts an element to JSON, typed by f when non-nil.
func ToJSON(n *Node, f *Field) any { return toJSON(n, f, 0) }

func isNil(n *Node) bool {
	for _, ns := range []string{NSXSI, nsXSI1999} {
		if v, ok := n.LookupAttr(ns, "nil"); ok && isTrue(v) {
			return true
		}
	}
	if v, ok := n.LookupAttr(nsXSI1999, "null"); ok && isTrue(v) {
		return true
	}
	return false
}

func toJSON(n *Node, f *Field, depth int) any {
	if f != nil {
		f = f.Expanded()
	}
	if isNil(n) {
		return nil
	}
	if depth > maxXMLDepth {
		return n.Text
	}
	var attrs [][2]string
	for _, a := range n.Attrs {
		if a.Name.Space == NSXSI || a.Name.Space == nsXSI1999 || a.Name.Space == "xmlns" {
			continue
		}
		attrs = append(attrs, [2]string{a.Name.Local, a.Value})
	}
	text := n.Text
	hasText := strings.TrimSpace(text) != ""
	complexField := f != nil && (len(f.Children) > 0 || len(f.Attrs) > 0 || f.HasText)
	if len(n.Children) == 0 && len(attrs) == 0 {
		switch {
		case f != nil && f.Simple != nil && !complexField:
			return typedValue(text, f.Simple)
		case complexField && !hasText:
			return NewOMap()
		case complexField && f.HasText:
			return typedValue(text, f.Simple)
		}
		return text
	}
	m := NewOMap()
	for _, a := range attrs {
		var v any = a[1]
		if f != nil {
			if af := f.FindAttr(a[0]); af != nil {
				si := af.Simple
				v = typedValue(a[1], &si)
			}
		}
		m.Set("@"+a[0], v)
	}
	if hasText && len(n.Children) == 0 {
		var si *SimpleInfo
		if f != nil {
			si = f.Simple
		}
		m.Set("#text", typedValue(text, si))
	}
	convertChildren(m, n.Children, func(local string) *Field {
		if f == nil {
			return nil
		}
		return f.FindChild(local)
	}, depth)
	if hasText && len(n.Children) > 0 {
		m.Set("#text", strings.Join(strings.Fields(text), " "))
	}
	return m
}

// convertChildren adds children to m, grouping repeated names into arrays.
func convertChildren(m *OMap, children []*Node, field func(local string) *Field, depth int) {
	type group struct {
		vals  []any
		array bool
	}
	groups := map[string]*group{}
	var order []string
	for _, c := range children {
		k := c.Name.Local
		if strings.HasPrefix(k, "@") || k == "#text" {
			k = "_" + k
		}
		cf := field(c.Name.Local)
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
			order = append(order, k)
		}
		if cf != nil && cf.IsArray() {
			g.array = true
		}
		g.vals = append(g.vals, toJSON(c, cf, depth+1))
	}
	for _, k := range order {
		g := groups[k]
		if g.array || len(g.vals) > 1 {
			m.Set(k, g.vals)
		} else {
			m.Set(k, g.vals[0])
		}
	}
}

func typedValue(text string, si *SimpleInfo) any {
	if si == nil {
		return text
	}
	if si.List {
		item := *si
		item.List = false
		fields := strings.Fields(text)
		out := make([]any, len(fields))
		for i, f := range fields {
			out[i] = typedValue(f, &item)
		}
		return out
	}
	t := strings.TrimSpace(text)
	switch JSONType(si.Base) {
	case "integer":
		if i, err := strconv.ParseInt(t, 10, 64); err == nil {
			return i
		}
		if u, err := strconv.ParseUint(t, 10, 64); err == nil {
			return u
		}
	case "number":
		if v, err := strconv.ParseFloat(t, 64); err == nil && !strings.ContainsAny(strings.ToLower(t), "inf nan") {
			return v
		}
	case "boolean":
		switch t {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
	}
	return text
}

// Fault is a parsed SOAP 1.1 or 1.2 fault.
type Fault struct {
	SOAPVersion string `json:"soap_version"`
	// SOAP 1.1
	FaultCode   string `json:"faultcode,omitempty"`
	FaultString string `json:"faultstring,omitempty"`
	FaultActor  string `json:"faultactor,omitempty"`
	// SOAP 1.2
	Code     string      `json:"code,omitempty"`
	Subcodes []string    `json:"subcodes,omitempty"`
	Reason   string      `json:"reason,omitempty"`
	Reasons  []FaultText `json:"reasons,omitempty"`
	Node     string      `json:"node,omitempty"`
	Role     string      `json:"role,omitempty"`
	Detail   any         `json:"detail,omitempty"`
}

// FaultText is a SOAP 1.2 Reason/Text with its language.
type FaultText struct {
	Lang string `json:"lang,omitempty"`
	Text string `json:"text"`
}

func childLocal(n *Node, local string) *Node {
	for _, c := range n.Children {
		if c.Name.Local == local {
			return c
		}
	}
	return nil
}

func trimmed(n *Node) string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.Text)
}

// ParseFault parses a soapenv:Fault element.
func ParseFault(n *Node, version string) *Fault {
	f := &Fault{SOAPVersion: version}
	var detail *Node
	if version == "1.2" {
		if code := childLocal(n, "Code"); code != nil {
			f.Code = trimmed(childLocal(code, "Value"))
			sub := childLocal(code, "Subcode")
			for i := 0; sub != nil && i < 16; i++ {
				f.Subcodes = append(f.Subcodes, trimmed(childLocal(sub, "Value")))
				sub = childLocal(sub, "Subcode")
			}
		}
		if reason := childLocal(n, "Reason"); reason != nil {
			for _, t := range reason.Children {
				if t.Name.Local != "Text" {
					continue
				}
				lang, _ := t.LookupAttr(nsXML, "lang")
				f.Reasons = append(f.Reasons, FaultText{Lang: lang, Text: strings.TrimSpace(t.Text)})
			}
			if len(f.Reasons) > 0 {
				f.Reason = f.Reasons[0].Text
			}
			if len(f.Reasons) < 2 {
				f.Reasons = nil
			}
		}
		f.Node = trimmed(childLocal(n, "Node"))
		f.Role = trimmed(childLocal(n, "Role"))
		detail = childLocal(n, "Detail")
	} else {
		f.FaultCode = trimmed(childLocal(n, "faultcode"))
		f.FaultString = trimmed(childLocal(n, "faultstring"))
		f.FaultActor = trimmed(childLocal(n, "faultactor"))
		detail = childLocal(n, "detail")
	}
	if detail != nil {
		f.Detail = toJSON(detail, nil, 0)
	}
	return f
}

// Response is a parsed SOAP response envelope.
type Response struct {
	SOAPVersion string
	Header      any
	Body        any
	Fault       *Fault
}

// ParseResponse parses a SOAP envelope. outFields types the body children
// (nil for untyped conversion); rpc lets the single wrapper match by
// position rather than by name.
func ParseResponse(data []byte, outFields []*Field, rpc bool) (*Response, error) {
	root, err := ParseXML(data)
	if err != nil {
		return nil, err
	}
	var version string
	switch {
	case root.Is(NSSOAP11Env, "Envelope"):
		version = "1.1"
	case root.Is(NSSOAP12Env, "Envelope"):
		version = "1.2"
	default:
		return nil, fmt.Errorf("response is not a SOAP envelope (root element {%s}%s)", root.Name.Space, root.Name.Local)
	}
	env := root.Name.Space
	r := &Response{SOAPVersion: version}
	if h := root.Child(env, "Header"); h != nil && len(h.Children) > 0 {
		hm := NewOMap()
		convertChildren(hm, h.Children, func(string) *Field { return nil }, 0)
		r.Header = hm
	}
	body := root.Child(env, "Body")
	if body == nil {
		return nil, fmt.Errorf("SOAP envelope has no Body")
	}
	var payload []*Node
	for _, c := range body.Children {
		if c.Is(env, "Fault") {
			if r.Fault == nil {
				r.Fault = ParseFault(c, version)
			}
			continue
		}
		payload = append(payload, c)
	}
	bm := NewOMap()
	lookupField := func(local string) *Field {
		for _, f := range outFields {
			if f.Name == local {
				return f
			}
		}
		if rpc && len(outFields) == 1 && len(payload) == 1 {
			cp := *outFields[0]
			cp.Name = local
			return &cp
		}
		return nil
	}
	convertChildren(bm, payload, lookupField, 0)
	r.Body = bm
	return r, nil
}

// OutputFields returns the fields typing a response for a concrete operation.
func (d *Definitions) OutputFields(o *OpBinding) []*Field {
	if o == nil || o.Op.Output.IsZero() {
		return nil
	}
	return d.Body(o, true).Fields
}
