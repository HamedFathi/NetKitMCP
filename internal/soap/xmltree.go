// Package soap implements the SOAP support of netkit-mcp by hand on top of
// encoding/xml: a WSDL 1.1 parser with import resolution, a practical XSD
// subset (rendered as JSON-like skeletons), an envelope builder that turns
// JSON arguments into document/rpc literal bodies, SOAP 1.1/1.2 fault
// parsing, XML-to-JSON conversion and WS-Security UsernameToken headers.
//
// Out of scope: WSDL 2.0, MTOM/XOP attachments, WS-Security signing and
// encryption, SOAP-encoded multi-reference graphs.
package soap

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html/charset"
)

// Well-known namespaces.
const (
	NSSOAP11Env  = "http://schemas.xmlsoap.org/soap/envelope/"
	NSSOAP12Env  = "http://www.w3.org/2003/05/soap-envelope"
	NSSOAPEnc    = "http://schemas.xmlsoap.org/soap/encoding/"
	NSWSDL       = "http://schemas.xmlsoap.org/wsdl/"
	NSWSDL20     = "http://www.w3.org/ns/wsdl"
	NSWSDLSOAP11 = "http://schemas.xmlsoap.org/wsdl/soap/"
	NSWSDLSOAP12 = "http://schemas.xmlsoap.org/wsdl/soap12/"
	NSWSDLHTTP   = "http://schemas.xmlsoap.org/wsdl/http/"
	NSWSDLMIME   = "http://schemas.xmlsoap.org/wsdl/mime/"
	NSXSD        = "http://www.w3.org/2001/XMLSchema"
	NSXSI        = "http://www.w3.org/2001/XMLSchema-instance"
	nsXSD1999    = "http://www.w3.org/1999/XMLSchema"
	nsXSD2000    = "http://www.w3.org/2000/10/XMLSchema"
	nsXSI1999    = "http://www.w3.org/1999/XMLSchema-instance"
	nsXML        = "http://www.w3.org/XML/1998/namespace"
)

const maxXMLDepth = 256

// Node is a minimal DOM element with the in-scope namespace declarations
// needed to resolve QName-valued attributes (type="tns:Foo").
type Node struct {
	Name     xml.Name          // Space is the namespace URI
	Attrs    []xml.Attr        // attributes except xmlns declarations
	NS       map[string]string // in-scope prefix -> URI ("" = default namespace)
	Children []*Node
	Text     string // character data directly inside this element
}

// ParseXML parses a document into a Node tree. Non-UTF-8 encodings declared
// in the XML prolog are converted.
func ParseXML(data []byte) (*Node, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		return charset.NewReaderLabel(label, r)
	}
	var root *Node
	var stack []*Node
	var texts []*strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxXMLDepth {
				return nil, fmt.Errorf("invalid XML: nesting deeper than %d levels", maxXMLDepth)
			}
			var parentNS map[string]string
			if len(stack) > 0 {
				parentNS = stack[len(stack)-1].NS
			}
			n := &Node{Name: t.Name, NS: parentNS}
			copied := false
			for _, a := range t.Attr {
				isDecl := a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns")
				if !isDecl {
					n.Attrs = append(n.Attrs, a)
					continue
				}
				if !copied {
					m := make(map[string]string, len(parentNS)+2)
					for k, v := range parentNS {
						m[k] = v
					}
					n.NS = m
					copied = true
				}
				if a.Name.Space == "xmlns" {
					n.NS[a.Name.Local] = a.Value
				} else {
					n.NS[""] = a.Value
				}
			}
			if n.NS == nil {
				n.NS = map[string]string{}
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, n)
			} else if root == nil {
				root = n
			} else {
				return nil, errors.New("invalid XML: multiple root elements")
			}
			stack = append(stack, n)
			texts = append(texts, &strings.Builder{})
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("invalid XML: unexpected end element")
			}
			stack[len(stack)-1].Text = texts[len(texts)-1].String()
			stack = stack[:len(stack)-1]
			texts = texts[:len(texts)-1]
		case xml.CharData:
			if len(texts) > 0 {
				texts[len(texts)-1].Write(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("invalid XML: no root element")
	}
	if len(stack) != 0 {
		return nil, errors.New("invalid XML: unexpected end of document")
	}
	return root, nil
}

// Is reports whether the node has the given namespace and local name.
func (n *Node) Is(space, local string) bool {
	return n != nil && n.Name.Space == space && n.Name.Local == local
}

// Attr returns an unqualified attribute value.
func (n *Node) Attr(local string) string {
	v, _ := n.LookupAttr("", local)
	return v
}

// LookupAttr returns an attribute by namespace and local name.
func (n *Node) LookupAttr(space, local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Space == space && a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// HasAttr reports whether an unqualified attribute is present.
func (n *Node) HasAttr(local string) bool {
	_, ok := n.LookupAttr("", local)
	return ok
}

// Child returns the first child with the given name.
func (n *Node) Child(space, local string) *Node {
	for _, c := range n.Children {
		if c.Is(space, local) {
			return c
		}
	}
	return nil
}

// ChildrenNamed returns the children with the given name.
func (n *Node) ChildrenNamed(space, local string) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.Is(space, local) {
			out = append(out, c)
		}
	}
	return out
}

// QName is a namespace-qualified name.
type QName struct {
	Space string `json:"namespace,omitempty"`
	Local string `json:"name"`
}

// IsZero reports whether the name is empty.
func (q QName) IsZero() bool { return q.Local == "" }

// String renders {ns}local.
func (q QName) String() string {
	if q.Space == "" {
		return q.Local
	}
	return "{" + q.Space + "}" + q.Local
}

// ResolveQName resolves a prefixed QName value using the node's in-scope
// namespaces. Unprefixed values take the default namespace.
func (n *Node) ResolveQName(v string) QName {
	v = strings.TrimSpace(v)
	if v == "" {
		return QName{}
	}
	prefix, local := "", v
	if i := strings.IndexByte(v, ':'); i >= 0 {
		prefix, local = v[:i], v[i+1:]
	}
	if prefix == "xml" {
		return QName{Space: nsXML, Local: local}
	}
	return QName{Space: n.NS[prefix], Local: local}
}

// OMap is a JSON object that preserves insertion order.
type OMap struct {
	keys []string
	vals map[string]any
}

// NewOMap creates an empty ordered map.
func NewOMap() *OMap { return &OMap{vals: map[string]any{}} }

// Set sets a key, keeping the position of an existing key.
func (m *OMap) Set(k string, v any) {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
}

// Get returns a value.
func (m *OMap) Get(k string) (any, bool) {
	v, ok := m.vals[k]
	return v, ok
}

// Has reports whether k is present.
func (m *OMap) Has(k string) bool {
	_, ok := m.vals[k]
	return ok
}

// Keys returns the keys in order.
func (m *OMap) Keys() []string { return m.keys }

// Len returns the number of keys.
func (m *OMap) Len() int { return len(m.keys) }

// MarshalJSON writes the keys in insertion order.
func (m *OMap) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(m.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
