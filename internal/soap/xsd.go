package soap

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// schemaDoc is one xs:schema element with its effective settings.
type schemaDoc struct {
	node          *Node
	tns           string
	elemQualified bool
	attrQualified bool
}

type decl struct {
	n *Node
	s *schemaDoc
}

// SchemaSet indexes the global components of every loaded schema.
type SchemaSet struct {
	elements   map[QName]decl
	types      map[QName]decl
	groups     map[QName]decl
	attrGroups map[QName]decl
	attributes map[QName]decl
	schemas    []*schemaDoc
	warned     map[string]bool
	Warnings   []string
}

func newSchemaSet() *SchemaSet {
	return &SchemaSet{
		elements:   map[QName]decl{},
		types:      map[QName]decl{},
		groups:     map[QName]decl{},
		attrGroups: map[QName]decl{},
		attributes: map[QName]decl{},
		warned:     map[string]bool{},
	}
}

func isXSDNS(ns string) bool { return ns == NSXSD || ns == nsXSD1999 || ns == nsXSD2000 }

// add indexes a schema element. tnsOverride is used for chameleon includes
// (an included schema without a targetNamespace adopts the includer's).
func (ss *SchemaSet) add(n *Node, tnsOverride string) *schemaDoc {
	tns := n.Attr("targetNamespace")
	if tns == "" && tnsOverride != "" {
		tns = tnsOverride
	}
	sd := &schemaDoc{
		node:          n,
		tns:           tns,
		elemQualified: n.Attr("elementFormDefault") == "qualified",
		attrQualified: n.Attr("attributeFormDefault") == "qualified",
	}
	ss.schemas = append(ss.schemas, sd)
	for _, c := range n.Children {
		if !isXSDNS(c.Name.Space) {
			continue
		}
		name := c.Attr("name")
		if name == "" {
			continue
		}
		q := QName{Space: tns, Local: name}
		var m map[QName]decl
		switch c.Name.Local {
		case "element":
			m = ss.elements
		case "complexType", "simpleType":
			m = ss.types
		case "group":
			m = ss.groups
		case "attributeGroup":
			m = ss.attrGroups
		case "attribute":
			m = ss.attributes
		default:
			continue
		}
		if _, dup := m[q]; !dup {
			m[q] = decl{c, sd}
		}
	}
	return sd
}

func (ss *SchemaSet) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if ss.warned[msg] {
		return
	}
	ss.warned[msg] = true
	if len(ss.Warnings) < 50 {
		ss.Warnings = append(ss.Warnings, msg)
	}
}

func lookup(m map[QName]decl, q QName) (decl, bool) {
	if d, ok := m[q]; ok {
		return d, true
	}
	// Be lenient with sloppy WSDLs whose prefixes do not match: fall back
	// to a unique local-name match.
	var found decl
	n := 0
	for k, d := range m {
		if k.Local == q.Local {
			found = d
			n++
		}
	}
	return found, n == 1
}

// Element returns the global element declaration as a resolved Field.
func (ss *SchemaSet) Element(q QName) (*Field, bool) {
	d, ok := lookup(ss.elements, q)
	if !ok {
		return nil, false
	}
	r := newResolver(ss)
	return r.element(d.n, d.s, true, 0), true
}

// TypeField builds a Field for a local element named name (namespace ns)
// whose type is q (used for rpc part accessors and type= parts).
func (ss *SchemaSet) TypeField(name, ns string, q QName) *Field {
	r := newResolver(ss)
	f := &Field{Kind: KindElement, Name: name, NS: ns, Min: 1, Max: 1}
	r.typeInto(f, q, 0)
	return f
}

// Field kinds.
const (
	KindElement  = "element"
	KindChoice   = "choice"
	KindSequence = "sequence"
	KindAny      = "any"
)

// Field is a resolved element declaration (or a choice/sequence/any
// particle) of the XSD subset.
type Field struct {
	Kind     string
	Name     string
	NS       string // element namespace ("" = unqualified)
	Type     QName  // declared named type, if any
	Min, Max int    // Max -1 = unbounded
	Nillable bool

	Simple   *SimpleInfo // set for simple content (leaf or simpleContent)
	Attrs    []*AttrField
	Children []*Field // content particles in order
	HasText  bool     // simpleContent: text plus attributes
	Mixed    bool
	AnyAttr  bool
	ChildNS  string // namespace given to unknown local child elements
	Encoded  string // soapenc array item type (rpc/encoded arrays)

	Recursive bool
	lazy      func() *Field
}

// SimpleInfo describes a simple type.
type SimpleInfo struct {
	Base string   // built-in XSD local name (string, int, dateTime, ...)
	Enum []string // enumeration facets
	List bool     // xs:list of Base
}

// AttrField is a resolved attribute.
type AttrField struct {
	Name     string
	NS       string
	Simple   SimpleInfo
	Required bool
	Fixed    string
}

// IsLeaf reports whether the element has only simple text and no
// attributes or child elements.
func (f *Field) IsLeaf() bool {
	return f.Kind == KindElement && f.Simple != nil && !f.HasText && len(f.Attrs) == 0 && len(f.Children) == 0 && !f.Recursive
}

// IsArray reports whether the particle may repeat.
func (f *Field) IsArray() bool { return f.Max != 1 && f.Max != 0 }

// Expanded returns f, expanding a recursive placeholder on demand.
func (f *Field) Expanded() *Field {
	if f != nil && f.Recursive && f.lazy != nil {
		e := f.lazy()
		e.Name, e.NS, e.Min, e.Max, e.Nillable = f.Name, f.NS, f.Min, f.Max, f.Nillable
		return e
	}
	return f
}

// FindChild finds an element particle by local name, searching through
// choice and sequence groups.
func (f *Field) FindChild(local string) *Field {
	for _, c := range f.Children {
		switch c.Kind {
		case KindElement:
			if c.Name == local {
				return c
			}
		case KindChoice, KindSequence:
			if m := c.FindChild(local); m != nil {
				if c.IsArray() && !m.IsArray() {
					cp := *m
					cp.Max = -1
					return &cp
				}
				return m
			}
		}
	}
	return nil
}

// FindAttr finds an attribute by local name.
func (f *Field) FindAttr(local string) *AttrField {
	for _, a := range f.Attrs {
		if a.Name == local {
			return a
		}
	}
	return nil
}

// HasAny reports whether the content allows xs:any.
func (f *Field) HasAny() bool {
	for _, c := range f.Children {
		if c.Kind == KindAny {
			return true
		}
		if (c.Kind == KindChoice || c.Kind == KindSequence) && c.HasAny() {
			return true
		}
	}
	return false
}

const maxResolveDepth = 32

type resolver struct {
	ss     *SchemaSet
	stack  map[QName]bool
	budget int // remaining element expansions
}

const resolveBudget = 4000

func newResolver(ss *SchemaSet) *resolver {
	return &resolver{ss: ss, stack: map[QName]bool{}, budget: resolveBudget}
}

func occurs(n *Node) (int, int) {
	min, max := 1, 1
	if v := n.Attr("minOccurs"); v != "" {
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			min = i
		}
	}
	if v := strings.TrimSpace(n.Attr("maxOccurs")); v != "" {
		if v == "unbounded" {
			max = -1
		} else if i, err := strconv.Atoi(v); err == nil {
			max = i
		}
	}
	return min, max
}

func isTrue(v string) bool {
	v = strings.TrimSpace(v)
	return v == "true" || v == "1"
}

func (r *resolver) element(n *Node, s *schemaDoc, top bool, depth int) *Field {
	if ref := n.Attr("ref"); ref != "" {
		q := n.ResolveQName(ref)
		var f *Field
		if d, ok := lookup(r.ss.elements, q); ok {
			key := QName{Space: "element " + d.s.tns, Local: d.n.Attr("name")}
			if r.stack[key] || depth > maxResolveDepth {
				ss := r.ss
				f = &Field{Kind: KindElement, Name: d.n.Attr("name"), NS: d.s.tns, Recursive: true, Type: QName{Space: d.s.tns, Local: d.n.Attr("name")}}
				f.lazy = func() *Field {
					nr := newResolver(ss)
					nr.stack[key] = true
					return nr.element(d.n, d.s, true, 0)
				}
			} else {
				r.stack[key] = true
				f = r.element(d.n, d.s, true, depth+1)
				delete(r.stack, key)
			}
		} else {
			r.ss.warn("unresolved element reference %s", q)
			f = &Field{Kind: KindElement, Name: q.Local, NS: q.Space, Simple: &SimpleInfo{Base: "string"}}
		}
		f.Min, f.Max = occurs(n)
		return f
	}
	f := &Field{Kind: KindElement, Name: n.Attr("name"), Min: 1, Max: 1}
	r.budget--
	if !top {
		f.Min, f.Max = occurs(n)
	}
	switch {
	case top:
		f.NS = s.tns
	case n.Attr("form") == "qualified":
		f.NS = s.tns
	case n.Attr("form") == "unqualified":
		f.NS = ""
	case s.elemQualified:
		f.NS = s.tns
	}
	f.Nillable = isTrue(n.Attr("nillable"))
	if depth > maxResolveDepth || r.budget < 0 {
		if r.budget < 0 {
			r.ss.warn("schema is very large; shapes were truncated (describe a single operation for details)")
		}
		f.Recursive = true
		ss := r.ss
		f.lazy = func() *Field {
			nr := newResolver(ss)
			return nr.element(n, s, top, 0)
		}
		return f
	}
	if t := n.Attr("type"); t != "" {
		r.typeInto(f, n.ResolveQName(t), depth)
		return f
	}
	if ct := n.Child(s.node.Name.Space, "complexType"); ct != nil {
		r.complexInto(f, ct, s, depth+1)
		return f
	}
	if st := n.Child(s.node.Name.Space, "simpleType"); st != nil {
		si := r.simple(st, s, depth+1)
		f.Simple = &si
		return f
	}
	// No type: xs:anyType.
	f.Simple = &SimpleInfo{Base: "anyType"}
	return f
}

// typeInto fills f with the content of the named type q.
func (r *resolver) typeInto(f *Field, q QName, depth int) {
	f.Type = q
	if isXSDNS(q.Space) || q.Space == NSSOAPEnc {
		if q.Space == NSSOAPEnc && q.Local == "Array" {
			f.Children = []*Field{{Kind: KindAny, Min: 0, Max: -1}}
			return
		}
		f.Simple = &SimpleInfo{Base: q.Local}
		return
	}
	d, ok := lookup(r.ss.types, q)
	if !ok {
		r.ss.warn("unresolved type %s (treated as string)", q)
		f.Simple = &SimpleInfo{Base: "string"}
		return
	}
	if d.n.Name.Local == "simpleType" {
		si := r.simple(d.n, d.s, depth+1)
		f.Simple = &si
		return
	}
	key := QName{Space: d.s.tns, Local: d.n.Attr("name")}
	if r.stack[key] || depth > maxResolveDepth {
		f.Recursive = true
		ss := r.ss
		f.lazy = func() *Field {
			nr := newResolver(ss)
			e := &Field{Kind: KindElement, Min: 1, Max: 1}
			nr.stack[key] = true
			nr.complexInto(e, d.n, d.s, 0)
			e.Type = key
			return e
		}
		return
	}
	r.stack[key] = true
	r.complexInto(f, d.n, d.s, depth+1)
	delete(r.stack, key)
}

func (r *resolver) complexInto(f *Field, ct *Node, s *schemaDoc, depth int) {
	if f.ChildNS == "" && s.elemQualified {
		f.ChildNS = s.tns
	}
	if isTrue(ct.Attr("mixed")) {
		f.Mixed = true
	}
	for _, c := range ct.Children {
		if !isXSDNS(c.Name.Space) {
			continue
		}
		switch c.Name.Local {
		case "sequence", "all", "choice", "group":
			r.particle(f, &f.Children, c, s, depth)
		case "attribute":
			f.Attrs = append(f.Attrs, r.attribute(c, s, depth))
		case "attributeGroup":
			r.attrGroup(f, c, depth)
		case "anyAttribute":
			f.AnyAttr = true
		case "simpleContent":
			r.simpleContent(f, c, s, depth)
		case "complexContent":
			r.complexContent(f, c, s, depth)
		}
	}
}

func (r *resolver) simpleContent(f *Field, sc *Node, s *schemaDoc, depth int) {
	f.HasText = true
	for _, c := range sc.Children {
		if c.Name.Local != "extension" && c.Name.Local != "restriction" {
			continue
		}
		base := c.ResolveQName(c.Attr("base"))
		switch {
		case base.IsZero():
			f.Simple = &SimpleInfo{Base: "string"}
		case isXSDNS(base.Space) || base.Space == NSSOAPEnc:
			f.Simple = &SimpleInfo{Base: base.Local}
		default:
			if d, ok := lookup(r.ss.types, base); ok && depth <= maxResolveDepth {
				if d.n.Name.Local == "simpleType" {
					si := r.simple(d.n, d.s, depth+1)
					f.Simple = &si
				} else {
					r.complexInto(f, d.n, d.s, depth+1)
				}
			} else {
				r.ss.warn("unresolved type %s (treated as string)", base)
				f.Simple = &SimpleInfo{Base: "string"}
			}
		}
		if f.Simple == nil {
			f.Simple = &SimpleInfo{Base: "string"}
		}
		if enum := enumerations(c); len(enum) > 0 {
			si := *f.Simple
			si.Enum = enum
			f.Simple = &si
		}
		for _, a := range c.Children {
			switch a.Name.Local {
			case "attribute":
				f.Attrs = append(f.Attrs, r.attribute(a, s, depth))
			case "attributeGroup":
				r.attrGroup(f, a, depth)
			case "anyAttribute":
				f.AnyAttr = true
			}
		}
	}
	f.HasText = true
}

func (r *resolver) complexContent(f *Field, cc *Node, s *schemaDoc, depth int) {
	if isTrue(cc.Attr("mixed")) {
		f.Mixed = true
	}
	for _, c := range cc.Children {
		if c.Name.Local != "extension" && c.Name.Local != "restriction" {
			continue
		}
		base := c.ResolveQName(c.Attr("base"))
		if base.Space == NSSOAPEnc && base.Local == "Array" {
			r.soapArray(f, c, s, depth)
			continue
		}
		if c.Name.Local == "extension" && !base.IsZero() && !isXSDNS(base.Space) {
			if d, ok := lookup(r.ss.types, base); ok {
				key := QName{Space: d.s.tns, Local: d.n.Attr("name")}
				if r.stack[key] || depth > maxResolveDepth {
					r.ss.warn("recursive base type %s not expanded", key)
				} else if d.n.Name.Local == "complexType" {
					r.stack[key] = true
					r.complexInto(f, d.n, d.s, depth+1)
					delete(r.stack, key)
				}
			} else {
				r.ss.warn("unresolved base type %s", base)
			}
		}
		// The extension's (or restriction's) own content follows the base content.
		for _, p := range c.Children {
			if !isXSDNS(p.Name.Space) {
				continue
			}
			switch p.Name.Local {
			case "sequence", "all", "choice", "group":
				r.particle(f, &f.Children, p, s, depth)
			case "attribute":
				f.Attrs = append(f.Attrs, r.attribute(p, s, depth))
			case "attributeGroup":
				r.attrGroup(f, p, depth)
			case "anyAttribute":
				f.AnyAttr = true
			}
		}
	}
}

// soapArray handles complexContent restrictions of soapenc:Array, reading
// the item type from wsdl:arrayType="tns:Item[]".
func (r *resolver) soapArray(f *Field, c *Node, s *schemaDoc, depth int) {
	var itemType QName
	var find func(n *Node)
	find = func(n *Node) {
		for _, a := range n.Children {
			if v, ok := a.LookupAttr(NSWSDL, "arrayType"); ok {
				v = strings.TrimSpace(v)
				if i := strings.IndexByte(v, '['); i >= 0 {
					v = v[:i]
				}
				itemType = a.ResolveQName(v)
				return
			}
			find(a)
		}
	}
	find(c)
	item := &Field{Kind: KindElement, Name: "item", Min: 0, Max: -1}
	if itemType.IsZero() {
		// Maybe a sequence of element items is declared explicitly.
		for _, p := range c.Children {
			if p.Name.Local == "sequence" || p.Name.Local == "all" {
				r.particle(f, &f.Children, p, s, depth)
			}
		}
		if len(f.Children) > 0 {
			for _, ch := range f.Children {
				ch.Min, ch.Max = 0, -1
			}
			return
		}
		item.Simple = &SimpleInfo{Base: "anyType"}
	} else {
		r.typeInto(item, itemType, depth+1)
		f.Encoded = itemType.Local
	}
	f.Children = []*Field{item}
}

// particle appends the content of a model group (sequence/all/choice/group
// reference) to out. Nested sequences are flattened; choices become a
// choice particle.
func (r *resolver) particle(f *Field, out *[]*Field, g *Node, s *schemaDoc, depth int) {
	if depth > maxResolveDepth {
		return
	}
	gmin, gmax := occurs(g)
	if g.Name.Local == "group" {
		ref := g.Attr("ref")
		if ref == "" {
			return
		}
		q := g.ResolveQName(ref)
		d, ok := lookup(r.ss.groups, q)
		if !ok {
			r.ss.warn("unresolved group %s", q)
			return
		}
		for _, c := range d.n.Children {
			switch c.Name.Local {
			case "sequence", "all", "choice":
				var tmp []*Field
				r.particle(f, &tmp, c, d.s, depth+1)
				adjust(tmp, gmin, gmax)
				*out = append(*out, tmp...)
			}
		}
		return
	}
	var items []*Field
	for _, c := range g.Children {
		if !isXSDNS(c.Name.Space) {
			continue
		}
		switch c.Name.Local {
		case "element":
			items = append(items, r.element(c, s, false, depth+1))
		case "sequence", "all":
			if g.Name.Local == "choice" {
				seq := &Field{Kind: KindSequence}
				seq.Min, seq.Max = occurs(c)
				r.particle(f, &seq.Children, c, s, depth+1)
				// The sequence's own occurrence was applied by the recursive call
				// to its children; keep the group itself as a single alternative.
				seq.Min, seq.Max = 1, 1
				items = append(items, seq)
			} else {
				r.particle(f, &items, c, s, depth+1)
			}
		case "choice", "group":
			r.particle(f, &items, c, s, depth+1)
		case "any":
			a := &Field{Kind: KindAny}
			a.Min, a.Max = occurs(c)
			items = append(items, a)
		}
	}
	if g.Name.Local == "choice" {
		ch := &Field{Kind: KindChoice, Min: gmin, Max: gmax, Children: items}
		*out = append(*out, ch)
		return
	}
	adjust(items, gmin, gmax)
	*out = append(*out, items...)
}

// adjust applies a flattened group's occurrence to its members.
func adjust(items []*Field, gmin, gmax int) {
	for _, it := range items {
		if gmin == 0 {
			it.Min = 0
		}
		if gmax != 1 {
			it.Max = -1
		}
	}
}

func (r *resolver) attribute(n *Node, s *schemaDoc, depth int) *AttrField {
	a := &AttrField{Simple: SimpleInfo{Base: "string"}}
	src, srcSchema := n, s
	if ref := n.Attr("ref"); ref != "" {
		q := n.ResolveQName(ref)
		a.Name, a.NS = q.Local, q.Space
		if d, ok := lookup(r.ss.attributes, q); ok {
			src, srcSchema = d.n, d.s
		} else {
			src = nil
		}
	} else {
		a.Name = n.Attr("name")
		switch {
		case n.Attr("form") == "qualified":
			a.NS = s.tns
		case n.Attr("form") == "unqualified":
		case s.attrQualified:
			a.NS = s.tns
		}
	}
	a.Required = n.Attr("use") == "required"
	a.Fixed = n.Attr("fixed")
	if src != nil {
		if t := src.Attr("type"); t != "" {
			q := src.ResolveQName(t)
			if isXSDNS(q.Space) || q.Space == NSSOAPEnc {
				a.Simple = SimpleInfo{Base: q.Local}
			} else if d, ok := lookup(r.ss.types, q); ok && d.n.Name.Local == "simpleType" {
				a.Simple = r.simple(d.n, d.s, depth+1)
			}
		} else if st := src.Child(srcSchema.node.Name.Space, "simpleType"); st != nil {
			a.Simple = r.simple(st, srcSchema, depth+1)
		}
	}
	return a
}

func (r *resolver) attrGroup(f *Field, n *Node, depth int) {
	if depth > maxResolveDepth {
		return
	}
	ref := n.Attr("ref")
	if ref == "" {
		return
	}
	q := n.ResolveQName(ref)
	d, ok := lookup(r.ss.attrGroups, q)
	if !ok {
		r.ss.warn("unresolved attributeGroup %s", q)
		return
	}
	for _, c := range d.n.Children {
		switch c.Name.Local {
		case "attribute":
			f.Attrs = append(f.Attrs, r.attribute(c, d.s, depth+1))
		case "attributeGroup":
			r.attrGroup(f, c, depth+1)
		case "anyAttribute":
			f.AnyAttr = true
		}
	}
}

func enumerations(n *Node) []string {
	var out []string
	for _, e := range n.Children {
		if e.Name.Local == "enumeration" && isXSDNS(e.Name.Space) {
			out = append(out, e.Attr("value"))
		}
	}
	return out
}

func (r *resolver) simple(st *Node, s *schemaDoc, depth int) SimpleInfo {
	si := SimpleInfo{Base: "string"}
	if depth > maxResolveDepth {
		return si
	}
	for _, c := range st.Children {
		if !isXSDNS(c.Name.Space) {
			continue
		}
		switch c.Name.Local {
		case "restriction":
			if b := c.Attr("base"); b != "" {
				si = r.simpleRef(c.ResolveQName(b), depth)
			} else if inner := c.Child(c.Name.Space, "simpleType"); inner != nil {
				si = r.simple(inner, s, depth+1)
			}
			if enum := enumerations(c); len(enum) > 0 {
				si.Enum = enum
			}
		case "list":
			var item SimpleInfo
			if t := c.Attr("itemType"); t != "" {
				item = r.simpleRef(c.ResolveQName(t), depth)
			} else if inner := c.Child(c.Name.Space, "simpleType"); inner != nil {
				item = r.simple(inner, s, depth+1)
			} else {
				item = SimpleInfo{Base: "string"}
			}
			item.List = true
			si = item
		case "union":
			si = SimpleInfo{Base: "string"}
		}
	}
	return si
}

func (r *resolver) simpleRef(q QName, depth int) SimpleInfo {
	if isXSDNS(q.Space) || q.Space == NSSOAPEnc {
		return SimpleInfo{Base: q.Local}
	}
	if d, ok := lookup(r.ss.types, q); ok && d.n.Name.Local == "simpleType" {
		return r.simple(d.n, d.s, depth+1)
	}
	r.ss.warn("unresolved simple type %s (treated as string)", q)
	return SimpleInfo{Base: "string"}
}

// JSONType maps a built-in XSD type to a JSON type.
func JSONType(base string) string {
	switch base {
	case "int", "integer", "long", "short", "byte", "unsignedInt", "unsignedLong", "unsignedShort",
		"unsignedByte", "nonNegativeInteger", "positiveInteger", "nonPositiveInteger", "negativeInteger":
		return "integer"
	case "decimal", "float", "double":
		return "number"
	case "boolean":
		return "boolean"
	case "anyType", "anySimpleType":
		return "any"
	}
	return "string"
}

// Describe renders a short type description for skeletons.
func (si SimpleInfo) Describe() string {
	var d string
	switch {
	case len(si.Enum) > 0:
		vals := si.Enum
		more := ""
		if len(vals) > 25 {
			vals = vals[:25]
			more = " | ..."
		}
		d = "enum: " + strings.Join(vals, " | ") + more
	default:
		jt := JSONType(si.Base)
		switch jt {
		case "string":
			switch si.Base {
			case "string", "normalizedString", "token", "":
				d = "string"
			default:
				d = "string:" + si.Base
			}
		default:
			d = jt
		}
	}
	if si.List {
		d = "list of " + d + " (space separated)"
	}
	return d
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
