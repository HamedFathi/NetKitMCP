package soap

import (
	"fmt"
	"strings"
)

// Skeleton conventions (also accepted by the envelope builder):
//
//   - keys are element local names; a trailing "?" marks minOccurs=0
//   - "@name" keys are attributes, "#text" is the text of simple content
//   - a value wrapped in [ ] may repeat (maxOccurs > 1)
//   - leaf values describe the type: "string", "integer", "number",
//     "boolean", "string:dateTime", "enum: A | B", "... | null" when nillable
//   - "#choice" lists alternatives of which one should be given
//   - "#any" means arbitrary XML elements are allowed

const maxSkeletonDepth = 12

// Skeletons renders a list of top-level fields as an ordered object.
func Skeletons(fields []*Field) *OMap {
	m := NewOMap()
	for _, f := range fields {
		renderParticle(m, f, 0, 0)
	}
	return m
}

// Skeleton renders the value of one element.
func (f *Field) Skeleton() any { return skeletonValue(f, 0) }

func skeletonValue(f *Field, depth int) any {
	if f.Recursive {
		if f.Type.Local != "" {
			return "recursive: " + f.Type.Local
		}
		return "recursive"
	}
	if depth > maxSkeletonDepth {
		return "..."
	}
	if f.IsLeaf() {
		d := f.Simple.Describe()
		if f.Nillable {
			d += " | null"
		}
		return d
	}
	m := NewOMap()
	for _, a := range f.Attrs {
		k := "@" + a.Name
		if !a.Required {
			k += "?"
		}
		d := a.Simple.Describe()
		if a.Fixed != "" {
			d = "fixed: " + a.Fixed
		}
		m.Set(k, d)
	}
	if f.HasText {
		si := f.Simple
		if si == nil {
			si = &SimpleInfo{Base: "string"}
		}
		m.Set("#text", si.Describe())
	}
	choices := 0
	for _, c := range f.Children {
		if c.Kind == KindChoice {
			choices++
			renderParticle(m, c, depth+1, choices)
		} else {
			renderParticle(m, c, depth+1, 0)
		}
	}
	if f.Mixed {
		m.Set("#text?", "string (mixed content)")
	}
	if f.Nillable {
		m.Set("#nillable", true)
	}
	return m
}

func renderParticle(m *OMap, f *Field, depth, choiceN int) {
	switch f.Kind {
	case KindAny:
		m.Set("#any", "any XML element(s)")
	case KindChoice:
		var names []string
		for _, alt := range f.Children {
			switch alt.Kind {
			case KindElement:
				names = append(names, alt.Name)
				cp := *alt
				cp.Min = 0
				if f.IsArray() {
					cp.Max = -1
				}
				renderParticle(m, &cp, depth, 0)
			case KindSequence:
				var group []string
				for _, s := range alt.Children {
					if s.Kind == KindElement {
						group = append(group, s.Name)
					}
					cp := *s
					cp.Min = 0
					renderParticle(m, &cp, depth, 0)
				}
				names = append(names, "("+strings.Join(group, " + ")+")")
			case KindAny:
				names = append(names, "any element")
				m.Set("#any", "any XML element(s)")
			}
		}
		key := "#choice"
		if choiceN > 1 {
			key = fmt.Sprintf("#choice%d", choiceN)
		}
		desc := "one of: " + strings.Join(names, " | ")
		if f.IsArray() {
			desc = "any number of: " + strings.Join(names, " | ")
		} else if f.Min == 0 {
			desc = "optional, " + desc
		}
		m.Set(key, desc)
	case KindSequence:
		for _, c := range f.Children {
			renderParticle(m, c, depth, 0)
		}
	default:
		k := f.Name
		if f.Min == 0 {
			k += "?"
		}
		v := skeletonValue(f, depth)
		if f.IsArray() {
			v = []any{v}
		}
		m.Set(k, v)
	}
}
