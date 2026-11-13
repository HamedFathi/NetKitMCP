package graphqlx

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// IntrospectionQuery is the standard introspection query (graphql-js
// getIntrospectionQuery with descriptions, compatible with older servers).
const IntrospectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}`

// Schema is the decoded __schema object.
type Schema struct {
	Description      *string     `json:"description"`
	QueryType        *namedType  `json:"queryType"`
	MutationType     *namedType  `json:"mutationType"`
	SubscriptionType *namedType  `json:"subscriptionType"`
	Types            []FullType  `json:"types"`
	Directives       []Directive `json:"directives"`
}

type namedType struct {
	Name string `json:"name"`
}

// FullType is an introspected type.
type FullType struct {
	Kind           string       `json:"kind"`
	Name           string       `json:"name"`
	Description    *string      `json:"description"`
	SpecifiedByURL *string      `json:"specifiedByURL"`
	Fields         []Field      `json:"fields"`
	InputFields    []InputValue `json:"inputFields"`
	Interfaces     []TypeRef    `json:"interfaces"`
	EnumValues     []EnumValue  `json:"enumValues"`
	PossibleTypes  []TypeRef    `json:"possibleTypes"`
}

// Field is an object or interface field.
type Field struct {
	Name              string       `json:"name"`
	Description       *string      `json:"description"`
	Args              []InputValue `json:"args"`
	Type              TypeRef      `json:"type"`
	IsDeprecated      bool         `json:"isDeprecated"`
	DeprecationReason *string      `json:"deprecationReason"`
}

// InputValue is an argument or input field.
type InputValue struct {
	Name              string  `json:"name"`
	Description       *string `json:"description"`
	Type              TypeRef `json:"type"`
	DefaultValue      *string `json:"defaultValue"`
	IsDeprecated      bool    `json:"isDeprecated"`
	DeprecationReason *string `json:"deprecationReason"`
}

// TypeRef is a (possibly wrapped) type reference.
type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   *string  `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

// EnumValue is an enum value.
type EnumValue struct {
	Name              string  `json:"name"`
	Description       *string `json:"description"`
	IsDeprecated      bool    `json:"isDeprecated"`
	DeprecationReason *string `json:"deprecationReason"`
}

// Directive is a directive definition.
type Directive struct {
	Name         string       `json:"name"`
	Description  *string      `json:"description"`
	IsRepeatable bool         `json:"isRepeatable"`
	Locations    []string     `json:"locations"`
	Args         []InputValue `json:"args"`
}

// DecodeSchema extracts __schema from introspection data. It accepts the
// `data` object ({"__schema": ...}) or a whole response ({"data": {...}}).
func DecodeSchema(raw []byte) (*Schema, error) {
	var w struct {
		Schema *Schema `json:"__schema"`
		Data   *struct {
			Schema *Schema `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("invalid introspection result: %w", err)
	}
	s := w.Schema
	if s == nil && w.Data != nil {
		s = w.Data.Schema
	}
	if s == nil {
		return nil, fmt.Errorf("introspection result has no __schema")
	}
	return s, nil
}

// PrintOptions control SDL output.
type PrintOptions struct {
	Descriptions bool
	// TypeName prints only that type (or directive when prefixed with @).
	TypeName string
}

var builtinScalars = map[string]bool{"String": true, "Int": true, "Float": true, "Boolean": true, "ID": true}
var builtinDirectives = map[string]bool{"skip": true, "include": true, "deprecated": true, "specifiedBy": true, "oneOf": true, "defer": true, "stream": true}

// Type finds a type by name.
func (s *Schema) Type(name string) *FullType {
	for i := range s.Types {
		if s.Types[i].Name == name {
			return &s.Types[i]
		}
	}
	return nil
}

// PrintSDL renders the schema (or a single type) as SDL.
func PrintSDL(s *Schema, o PrintOptions) (string, error) {
	p := &printer{opts: o}
	if o.TypeName != "" {
		name := o.TypeName
		if strings.HasPrefix(name, "@") {
			for _, d := range s.Directives {
				if d.Name == name[1:] {
					p.directive(d)
					return p.String(), nil
				}
			}
			return "", fmt.Errorf("directive %s not found", name)
		}
		t := s.Type(name)
		if t == nil {
			return "", fmt.Errorf("type %q not found in schema%s", name, suggest(s, name))
		}
		p.typ(*t)
		return p.String(), nil
	}
	p.schemaDef(s)
	for _, d := range s.Directives {
		if builtinDirectives[d.Name] {
			continue
		}
		p.directive(d)
	}
	for _, t := range s.Types {
		if strings.HasPrefix(t.Name, "__") || (t.Kind == "SCALAR" && builtinScalars[t.Name]) {
			continue
		}
		p.typ(t)
	}
	return p.String(), nil
}

func suggest(s *Schema, name string) string {
	var c []string
	ln := strings.ToLower(name)
	for _, t := range s.Types {
		lt := strings.ToLower(t.Name)
		if strings.HasPrefix(lt, "__") {
			continue
		}
		if strings.Contains(lt, ln) || (strings.Contains(ln, lt) && len(lt) > 2) || levenshtein(ln, lt) <= 2 {
			c = append(c, t.Name)
		}
	}
	sort.Strings(c)
	if len(c) > 10 {
		c = c[:10]
	}
	if len(c) == 0 {
		return ""
	}
	return " (similar: " + strings.Join(c, ", ") + ")"
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

type printer struct {
	opts  PrintOptions
	b     strings.Builder
	first bool
}

func (p *printer) String() string { return strings.TrimRight(p.b.String(), "\n") + "\n" }

func (p *printer) block() {
	if p.first {
		p.b.WriteString("\n")
	}
	p.first = true
}

func (p *printer) schemaDef(s *Schema) {
	q, m, sub := "", "", ""
	if s.QueryType != nil {
		q = s.QueryType.Name
	}
	if s.MutationType != nil {
		m = s.MutationType.Name
	}
	if s.SubscriptionType != nil {
		sub = s.SubscriptionType.Name
	}
	hasDesc := p.opts.Descriptions && s.Description != nil && *s.Description != ""
	if !hasDesc && (q == "" || q == "Query") && (m == "" || m == "Mutation") && (sub == "" || sub == "Subscription") {
		return
	}
	p.block()
	if hasDesc {
		p.desc(s.Description, "")
	}
	p.b.WriteString("schema {\n")
	if q != "" {
		fmt.Fprintf(&p.b, "  query: %s\n", q)
	}
	if m != "" {
		fmt.Fprintf(&p.b, "  mutation: %s\n", m)
	}
	if sub != "" {
		fmt.Fprintf(&p.b, "  subscription: %s\n", sub)
	}
	p.b.WriteString("}\n")
}

func (p *printer) desc(d *string, indent string) {
	if !p.opts.Descriptions || d == nil || *d == "" {
		return
	}
	s := *d
	if !strings.Contains(s, "\n") && !strings.Contains(s, `"""`) {
		b, _ := json.Marshal(s)
		p.b.WriteString(indent + string(b) + "\n")
		return
	}
	p.b.WriteString(indent + `"""` + "\n")
	for _, line := range strings.Split(strings.ReplaceAll(s, `"""`, `\"""`), "\n") {
		if line == "" {
			p.b.WriteString("\n")
		} else {
			p.b.WriteString(indent + line + "\n")
		}
	}
	p.b.WriteString(indent + `"""` + "\n")
}

func (p *printer) typ(t FullType) {
	p.block()
	p.desc(t.Description, "")
	switch t.Kind {
	case "SCALAR":
		p.b.WriteString("scalar " + t.Name)
		if t.SpecifiedByURL != nil && *t.SpecifiedByURL != "" {
			b, _ := json.Marshal(*t.SpecifiedByURL)
			p.b.WriteString(" @specifiedBy(url: " + string(b) + ")")
		}
		p.b.WriteString("\n")
	case "OBJECT", "INTERFACE":
		kw := "type"
		if t.Kind == "INTERFACE" {
			kw = "interface"
		}
		p.b.WriteString(kw + " " + t.Name)
		if len(t.Interfaces) > 0 {
			names := make([]string, len(t.Interfaces))
			for i, it := range t.Interfaces {
				names[i] = typeString(it)
			}
			p.b.WriteString(" implements " + strings.Join(names, " & "))
		}
		if len(t.Fields) == 0 {
			p.b.WriteString("\n")
			return
		}
		p.b.WriteString(" {\n")
		for _, f := range t.Fields {
			p.desc(f.Description, "  ")
			p.b.WriteString("  " + f.Name)
			p.args(f.Args, "  ")
			p.b.WriteString(": " + typeString(f.Type))
			p.deprecated(f.IsDeprecated, f.DeprecationReason)
			p.b.WriteString("\n")
		}
		p.b.WriteString("}\n")
	case "UNION":
		p.b.WriteString("union " + t.Name)
		if len(t.PossibleTypes) > 0 {
			names := make([]string, len(t.PossibleTypes))
			for i, it := range t.PossibleTypes {
				names[i] = typeString(it)
			}
			p.b.WriteString(" = " + strings.Join(names, " | "))
		}
		p.b.WriteString("\n")
	case "ENUM":
		p.b.WriteString("enum " + t.Name + " {\n")
		for _, v := range t.EnumValues {
			p.desc(v.Description, "  ")
			p.b.WriteString("  " + v.Name)
			p.deprecated(v.IsDeprecated, v.DeprecationReason)
			p.b.WriteString("\n")
		}
		p.b.WriteString("}\n")
	case "INPUT_OBJECT":
		p.b.WriteString("input " + t.Name + " {\n")
		for _, f := range t.InputFields {
			p.desc(f.Description, "  ")
			p.b.WriteString("  " + inputValueString(f))
			p.deprecated(f.IsDeprecated, f.DeprecationReason)
			p.b.WriteString("\n")
		}
		p.b.WriteString("}\n")
	default:
		fmt.Fprintf(&p.b, "# %s %s (unknown kind)\n", t.Kind, t.Name)
	}
}

func (p *printer) args(args []InputValue, indent string) {
	if len(args) == 0 {
		return
	}
	multiline := false
	if p.opts.Descriptions {
		for _, a := range args {
			if a.Description != nil && *a.Description != "" {
				multiline = true
				break
			}
		}
	}
	if !multiline {
		parts := make([]string, len(args))
		for i, a := range args {
			parts[i] = inputValueString(a)
			if a.IsDeprecated {
				parts[i] += deprecatedString(a.DeprecationReason)
			}
		}
		p.b.WriteString("(" + strings.Join(parts, ", ") + ")")
		return
	}
	p.b.WriteString("(\n")
	for _, a := range args {
		p.desc(a.Description, indent+"  ")
		p.b.WriteString(indent + "  " + inputValueString(a))
		if a.IsDeprecated {
			p.b.WriteString(deprecatedString(a.DeprecationReason))
		}
		p.b.WriteString("\n")
	}
	p.b.WriteString(indent + ")")
}

func (p *printer) deprecated(is bool, reason *string) {
	if is {
		p.b.WriteString(deprecatedString(reason))
	}
}

func deprecatedString(reason *string) string {
	if reason == nil || *reason == "" || *reason == "No longer supported" {
		return " @deprecated"
	}
	b, _ := json.Marshal(*reason)
	return " @deprecated(reason: " + string(b) + ")"
}

func (p *printer) directive(d Directive) {
	p.block()
	p.desc(d.Description, "")
	p.b.WriteString("directive @" + d.Name)
	p.args(d.Args, "")
	if d.IsRepeatable {
		p.b.WriteString(" repeatable")
	}
	p.b.WriteString(" on " + strings.Join(d.Locations, " | ") + "\n")
}

func inputValueString(v InputValue) string {
	s := v.Name + ": " + typeString(v.Type)
	if v.DefaultValue != nil {
		s += " = " + *v.DefaultValue
	}
	return s
}

func typeString(t TypeRef) string {
	switch t.Kind {
	case "NON_NULL":
		if t.OfType == nil {
			return "!"
		}
		return typeString(*t.OfType) + "!"
	case "LIST":
		if t.OfType == nil {
			return "[]"
		}
		return "[" + typeString(*t.OfType) + "]"
	}
	if t.Name != nil {
		return *t.Name
	}
	return "?"
}

// RootTypes returns the operation root type names.
func (s *Schema) RootTypes() map[string]string {
	m := map[string]string{}
	if s.QueryType != nil {
		m["query"] = s.QueryType.Name
	}
	if s.MutationType != nil {
		m["mutation"] = s.MutationType.Name
	}
	if s.SubscriptionType != nil {
		m["subscription"] = s.SubscriptionType.Name
	}
	return m
}

// Counts summarises a schema.
func (s *Schema) Counts() map[string]int {
	c := map[string]int{}
	for _, t := range s.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		c[strings.ToLower(t.Kind)]++
	}
	return c
}
