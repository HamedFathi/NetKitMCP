package soap

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// EnvNS returns the envelope namespace of a SOAP version ("1.1" or "1.2").
func EnvNS(version string) string {
	if version == "1.2" {
		return NSSOAP12Env
	}
	return NSSOAP11Env
}

// NormalizeVersion maps user input to "1.1", "1.2" or "" (unset).
func NormalizeVersion(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return "", nil
	case "1.1", "11", "soap11", "soap1.1":
		return "1.1", nil
	case "1.2", "12", "soap12", "soap1.2":
		return "1.2", nil
	}
	return "", fmt.Errorf("unsupported soap_version %q (use 1.1 or 1.2)", v)
}

// Elem is an element to serialize.
type Elem struct {
	NS, Local string
	Attrs     []XAttr
	Children  []*Elem
	Text      string
	Nil       bool
}

// XAttr is an attribute; QValue makes the value a QName (prefix resolved
// at serialization).
type XAttr struct {
	NS, Local string
	Value     string
	QValue    *QName
}

// Builder turns JSON arguments into body elements following the schema.
type Builder struct {
	Encoded  bool   // rpc/encoded: add xsi:type to simple values
	EnvNS    string // envelope namespace (for soapenv:encodingStyle)
	Warnings []string
}

func (b *Builder) warn(format string, args ...any) {
	if len(b.Warnings) < 50 {
		b.Warnings = append(b.Warnings, fmt.Sprintf(format, args...))
	}
}

// BuildBody builds the body children for an operation input from args.
func (b *Builder) BuildBody(bs *BodyShape, rpc bool, args any) ([]*Elem, error) {
	fields := bs.Fields
	if len(fields) == 0 {
		if !isEmptyArgs(args) {
			return nil, errors.New("this operation has no input body parts; omit args")
		}
		return nil, nil
	}
	if len(fields) == 1 {
		f := fields[0]
		v := unwrapArgs(f, args)
		if v == nil && !f.Nillable {
			v = map[string]any{}
		}
		if rpc && b.Encoded {
			el := b.single(f, v, f.Name)
			el.Attrs = append(el.Attrs, XAttr{NS: b.EnvNS, Local: "encodingStyle", Value: NSSOAPEnc})
			return []*Elem{el}, nil
		}
		return b.values(f, v, f.Name), nil
	}
	m, ok := args.(map[string]any)
	if !ok && !isEmptyArgs(args) {
		return nil, fmt.Errorf("args must be an object keyed by body element name (%s)", fieldNames(fields))
	}
	used := map[string]bool{}
	var out []*Elem
	for i, f := range fields {
		keys := []string{f.Name, f.Name + "?"}
		if i < len(bs.Parts) {
			keys = append(keys, bs.Parts[i].Name)
		}
		found := false
		for _, k := range keys {
			if v, ok := m[k]; ok {
				used[k] = true
				out = append(out, b.values(f, v, f.Name)...)
				found = true
				break
			}
		}
		if !found {
			b.warn("missing body element %s", f.Name)
		}
	}
	for _, k := range sortedKeys(m) {
		if !used[k] {
			b.warn("args key %q does not match a body part and was ignored", k)
		}
	}
	return out, nil
}

func fieldNames(fs []*Field) string {
	var n []string
	for _, f := range fs {
		n = append(n, f.Name)
	}
	return strings.Join(n, ", ")
}

func isEmptyArgs(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// unwrapArgs accepts both the element content and {"<Element>": content}.
func unwrapArgs(f *Field, args any) any {
	m, ok := args.(map[string]any)
	if !ok || len(m) != 1 {
		return args
	}
	for _, k := range []string{f.Name, f.Name + "?"} {
		if v, ok := m[k]; ok {
			ef := f.Expanded()
			if ef.FindChild(f.Name) == nil {
				return v
			}
		}
	}
	return args
}

// values builds one element per array item (or one for a single value).
func (b *Builder) values(f *Field, v any, path string) []*Elem {
	ef := f.Expanded()
	isList := ef.Simple != nil && ef.Simple.List && len(ef.Children) == 0
	if arr, ok := v.([]any); ok && !(isList && !f.IsArray()) {
		if !f.IsArray() && len(arr) != 1 {
			b.warn("%s: %d values given but the element does not repeat (maxOccurs=1)", path, len(arr))
		}
		out := make([]*Elem, 0, len(arr))
		for i, item := range arr {
			out = append(out, b.single(f, item, fmt.Sprintf("%s[%d]", path, i)))
		}
		return out
	}
	return []*Elem{b.single(f, v, path)}
}

func (b *Builder) single(f *Field, v any, path string) *Elem {
	f = f.Expanded()
	e := &Elem{NS: f.NS, Local: f.Name}
	if v == nil {
		e.Nil = true
		if !f.Nillable {
			b.warn("%s: null given but the element is not nillable", path)
		}
		return e
	}
	if f.Simple != nil && len(f.Children) == 0 && !f.HasText && len(f.Attrs) == 0 && !f.Mixed {
		if JSONType(f.Simple.Base) == "any" {
			if m, ok := v.(map[string]any); ok {
				return genericElem(f.NS, f.Name, m, f.NS, b)
			}
		}
		e.Text = b.scalar(v, f.Simple, path)
		if b.Encoded && JSONType(f.Simple.Base) != "any" {
			e.Attrs = append(e.Attrs, XAttr{NS: NSXSI, Local: "type", QValue: &QName{Space: NSXSD, Local: f.Simple.Base}})
		}
		return e
	}
	m, ok := v.(map[string]any)
	if !ok {
		if f.HasText || f.Mixed {
			e.Text = b.scalar(v, f.Simple, path)
			return e
		}
		if arr, isArr := v.([]any); isArr && f.Encoded != "" && len(f.Children) == 1 {
			// soapenc array given directly as a JSON array.
			m = map[string]any{f.Children[0].Name: arr}
		} else {
			b.warn("%s: expected an object, got %s", path, jsonKind(v))
			e.Text = b.scalar(v, nil, path)
			return e
		}
	}
	used := map[string]bool{}
	for _, a := range f.Attrs {
		for _, k := range []string{"@" + a.Name, "@" + a.Name + "?"} {
			if av, ok := m[k]; ok {
				used[k] = true
				si := a.Simple
				e.Attrs = append(e.Attrs, XAttr{NS: a.NS, Local: a.Name, Value: b.scalar(av, &si, path+"/@"+a.Name)})
				break
			}
		}
		if !used["@"+a.Name] && !used["@"+a.Name+"?"] && a.Required {
			if a.Fixed != "" {
				e.Attrs = append(e.Attrs, XAttr{NS: a.NS, Local: a.Name, Value: a.Fixed})
			} else {
				b.warn("%s: missing required attribute @%s", path, a.Name)
			}
		}
	}
	if f.Encoded != "" {
		n := 0
		if len(f.Children) == 1 {
			if arr, ok := m[f.Children[0].Name].([]any); ok {
				n = len(arr)
			}
		}
		e.Attrs = append(e.Attrs, XAttr{NS: NSSOAPEnc, Local: "arrayType", Value: fmt.Sprintf("%s[%d]", f.Encoded, n)})
		e.Attrs = append(e.Attrs, XAttr{NS: NSXSI, Local: "type", QValue: &QName{Space: NSSOAPEnc, Local: "Array"}})
	}
	if t, ok := m["#text"]; ok {
		used["#text"] = true
		e.Text = b.scalar(t, f.Simple, path)
	}
	b.particles(e, f.Children, m, used, path, true)
	childNS := f.ChildNS
	anyOK := f.HasAny()
	for _, k := range sortedKeys(m) {
		if used[k] {
			continue
		}
		switch {
		case strings.HasPrefix(k, "@"):
			if !f.AnyAttr {
				b.warn("%s: unknown attribute %s", path, k)
			}
			e.Attrs = append(e.Attrs, XAttr{Local: strings.TrimSuffix(k[1:], "?"), Value: b.scalar(m[k], nil, path+"/"+k)})
		case strings.HasPrefix(k, "#"):
			b.warn("%s: key %s ignored", path, k)
		default:
			if !anyOK {
				b.warn("%s: %s is not declared in the schema; sent as an element in namespace %q", path, k, childNS)
			}
			e.Children = append(e.Children, genericValues(childNS, strings.TrimSuffix(k, "?"), m[k], b)...)
		}
	}
	return e
}

func (b *Builder) particles(e *Elem, fields []*Field, m map[string]any, used map[string]bool, path string, required bool) {
	for _, c := range fields {
		switch c.Kind {
		case KindElement:
			found := false
			for _, k := range []string{c.Name, c.Name + "?"} {
				if v, ok := m[k]; ok {
					used[k] = true
					e.Children = append(e.Children, b.values(c, v, path+"/"+c.Name)...)
					found = true
					break
				}
			}
			if !found && required && c.Min > 0 {
				b.warn("%s: missing required element %s", path, c.Name)
			}
		case KindChoice:
			before := len(e.Children)
			b.particles(e, c.Children, m, used, path, false)
			if len(e.Children) == before && c.Min > 0 && required {
				var names []string
				for _, alt := range c.Children {
					if alt.Name != "" {
						names = append(names, alt.Name)
					}
				}
				if len(names) > 0 {
					b.warn("%s: none of the choice elements given (%s)", path, strings.Join(names, " | "))
				}
			}
		case KindSequence:
			b.particles(e, c.Children, m, used, path, false)
		}
	}
}

func genericValues(ns, name string, v any, b *Builder) []*Elem {
	if arr, ok := v.([]any); ok {
		var out []*Elem
		for _, it := range arr {
			out = append(out, genericValues(ns, name, it, b)...)
		}
		return out
	}
	switch t := v.(type) {
	case nil:
		return []*Elem{{NS: ns, Local: name, Nil: true}}
	case map[string]any:
		return []*Elem{genericElem(ns, name, t, ns, b)}
	}
	return []*Elem{{NS: ns, Local: name, Text: b.scalar(v, nil, name)}}
}

func genericElem(ns, name string, m map[string]any, childNS string, b *Builder) *Elem {
	e := &Elem{NS: ns, Local: name}
	for _, k := range sortedKeys(m) {
		switch {
		case strings.HasPrefix(k, "@"):
			e.Attrs = append(e.Attrs, XAttr{Local: strings.TrimSuffix(k[1:], "?"), Value: b.scalar(m[k], nil, k)})
		case k == "#text":
			e.Text = b.scalar(m[k], nil, k)
		case strings.HasPrefix(k, "#"):
		default:
			e.Children = append(e.Children, genericValues(childNS, strings.TrimSuffix(k, "?"), m[k], b)...)
		}
	}
	return e
}

func jsonKind(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case float64, json.Number, int, int64:
		return "a number"
	case bool:
		return "a boolean"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}

func (b *Builder) scalar(v any, si *SimpleInfo, path string) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if si != nil && JSONType(si.Base) == "integer" && t != math.Trunc(t) {
			b.warn("%s: %v is not an integer", path, t)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case nil:
		return ""
	case []any:
		if si != nil && si.List {
			parts := make([]string, len(t))
			for i, x := range t {
				parts[i] = b.scalar(x, nil, path)
			}
			return strings.Join(parts, " ")
		}
	}
	b.warn("%s: expected a simple value, got %s (sent as JSON text)", path, jsonKind(v))
	data, _ := json.Marshal(v)
	return string(data)
}

// Serializer writes Elem trees with generated namespace prefixes.
type Serializer struct {
	prefixes map[string]string
	used     map[string]bool
	declared map[string]bool // namespaces declared by an enclosing element
	n        int
	Indent   string
}

// NewSerializer creates a serializer; predeclared maps namespaces already
// declared by an enclosing element (e.g. the envelope) to their prefixes.
func NewSerializer(predeclared map[string]string) *Serializer {
	s := &Serializer{prefixes: map[string]string{}, used: map[string]bool{}, declared: map[string]bool{}, Indent: "  "}
	for ns, p := range predeclared {
		s.prefixes[ns] = p
		s.used[p] = true
		s.declared[ns] = true
	}
	return s
}

var wellKnownPrefixes = map[string]string{
	NSXSI: "xsi", NSXSD: "xsd", NSSOAPEnc: "soapenc",
}

func (s *Serializer) prefix(ns string) string {
	if p, ok := s.prefixes[ns]; ok {
		return p
	}
	p := wellKnownPrefixes[ns]
	if p == "" || s.used[p] {
		for {
			s.n++
			p = fmt.Sprintf("ns%d", s.n)
			if !s.used[p] {
				break
			}
		}
	}
	s.prefixes[ns] = p
	s.used[p] = true
	return p
}

// Write serializes roots, each declaring the namespaces used in its subtree
// (except predeclared ones). level is the starting indentation level.
func (s *Serializer) Write(roots []*Elem, level int) string {
	var b strings.Builder
	for i, r := range roots {
		if i > 0 {
			b.WriteString("\n")
			b.WriteString(strings.Repeat(s.Indent, level))
		}
		var decl strings.Builder
		seen := map[string]bool{}
		collectNS(r, func(ns string) {
			if ns == "" || seen[ns] || s.declared[ns] {
				return
			}
			seen[ns] = true
			fmt.Fprintf(&decl, ` xmlns:%s="%s"`, s.prefix(ns), escAttr(ns))
		})
		s.elem(&b, r, level, decl.String())
	}
	return b.String()
}

func collectNS(e *Elem, add func(string)) {
	add(e.NS)
	for _, a := range e.Attrs {
		add(a.NS)
		if a.QValue != nil {
			add(a.QValue.Space)
		}
	}
	if e.Nil {
		add(NSXSI)
	}
	for _, c := range e.Children {
		collectNS(c, add)
	}
}

func (s *Serializer) name(ns, local string) string {
	if ns == "" {
		return local
	}
	return s.prefix(ns) + ":" + local
}

func (s *Serializer) elem(b *strings.Builder, e *Elem, level int, decl string) {
	name := s.name(e.NS, e.Local)
	b.WriteString("<")
	b.WriteString(name)
	b.WriteString(decl)
	for _, a := range e.Attrs {
		v := a.Value
		if a.QValue != nil {
			v = s.name(a.QValue.Space, a.QValue.Local)
		}
		fmt.Fprintf(b, ` %s="%s"`, s.name(a.NS, a.Local), escAttr(v))
	}
	if e.Nil {
		fmt.Fprintf(b, ` %s:nil="true"`, s.prefix(NSXSI))
	}
	if len(e.Children) == 0 && e.Text == "" {
		b.WriteString("/>")
		return
	}
	b.WriteString(">")
	if e.Text != "" {
		xml.EscapeText(b2w{b}, []byte(e.Text))
	}
	if len(e.Children) > 0 {
		for _, c := range e.Children {
			b.WriteString("\n")
			b.WriteString(strings.Repeat(s.Indent, level+1))
			s.elem(b, c, level+1, "")
		}
		b.WriteString("\n")
		b.WriteString(strings.Repeat(s.Indent, level))
	}
	b.WriteString("</")
	b.WriteString(name)
	b.WriteString(">")
}

type b2w struct{ b *strings.Builder }

func (w b2w) Write(p []byte) (int, error) { return w.b.Write(p) }

func escAttr(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return strings.ReplaceAll(buf.String(), `"`, "&#34;")
}

// SerializeBody serializes body elements for placement inside soapenv:Body.
func SerializeBody(elems []*Elem, version string) string {
	s := NewSerializer(map[string]string{EnvNS(version): "soapenv"})
	return s.Write(elems, 2)
}

// Envelope assembles a SOAP envelope with the "soapenv" prefix.
func Envelope(version string, headers []string, body string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	fmt.Fprintf(&b, `<soapenv:Envelope xmlns:soapenv="%s">`, EnvNS(version))
	if len(headers) > 0 {
		b.WriteString("\n  <soapenv:Header>")
		for _, h := range headers {
			b.WriteString("\n    ")
			b.WriteString(strings.TrimSpace(h))
		}
		b.WriteString("\n  </soapenv:Header>")
	}
	b.WriteString("\n  <soapenv:Body>")
	if strings.TrimSpace(body) != "" {
		b.WriteString("\n    ")
		b.WriteString(strings.TrimSpace(body))
	}
	b.WriteString("\n  </soapenv:Body>\n</soapenv:Envelope>\n")
	return b.String()
}

// CheckFragment verifies that s is well-formed XML content (one or more
// elements, possibly with undeclared prefixes resolved by the envelope).
func CheckFragment(s string) error {
	d := xml.NewDecoder(strings.NewReader("<x>" + s + "</x>"))
	d.Strict = true
	for {
		_, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

var envStartRe = regexp.MustCompile(`^<([A-Za-z_][\w.-]*:)?Envelope\b`)

// RawEnvelope inspects a raw_body. If it is a full envelope it returns its
// SOAP version (from the namespace) and the envelope with extra header
// blocks injected; otherwise isEnvelope is false.
func RawEnvelope(raw string, headers []string) (out string, version string, isEnvelope bool, err error) {
	data := []byte(raw)
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	depth := 0
	var envPrefix string
	for {
		start := d.InputOffset()
		tok, terr := d.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			if depth == 0 && !isEnvelope {
				return "", "", false, nil
			}
			return "", "", true, fmt.Errorf("raw_body is not well-formed XML: %w", terr)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if t.Name.Local != "Envelope" || (t.Name.Space != NSSOAP11Env && t.Name.Space != NSSOAP12Env) {
					return "", "", false, nil
				}
				isEnvelope = true
				version = "1.1"
				if t.Name.Space == NSSOAP12Env {
					version = "1.2"
				}
				// Validate the whole envelope up front: it may be sent
				// as is, so a truncated or malformed document must not
				// slip through.
				root, perr := ParseXML(data)
				if perr != nil {
					return "", version, true, fmt.Errorf("raw_body is not well-formed XML: %w", perr)
				}
				if root.Child(t.Name.Space, "Body") == nil {
					return "", version, true, errors.New("raw_body envelope has no Body element")
				}
				if m := envStartRe.FindStringSubmatch(raw[start:]); m != nil {
					envPrefix = m[1]
				}
				if len(headers) == 0 {
					return raw, version, true, nil
				}
			} else if depth == 1 {
				block := strings.Join(headers, "")
				end := d.InputOffset()
				if t.Name.Local == "Header" {
					if strings.HasSuffix(raw[:end], "/>") {
						tag := raw[start : end-2]
						return raw[:start] + tag + ">" + block + "</" + envPrefix + "Header>" + raw[end:], version, true, nil
					}
					return raw[:end] + block + raw[end:], version, true, nil
				}
				hdr := "<" + envPrefix + "Header>" + block + "</" + envPrefix + "Header>"
				return raw[:start] + hdr + raw[start:], version, true, nil
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	if isEnvelope {
		return "", version, true, errors.New("raw_body envelope has no Body element")
	}
	return "", "", false, nil
}
