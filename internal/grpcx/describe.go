package grpcx

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// MethodInfo describes an RPC method.
type MethodInfo struct {
	Name            string `json:"name"`
	FullName        string `json:"full_name"`
	Path            string `json:"path"`
	InputType       string `json:"input_type"`
	OutputType      string `json:"output_type"`
	ClientStreaming bool   `json:"client_streaming"`
	ServerStreaming bool   `json:"server_streaming"`
	Kind            string `json:"kind"`
	Comment         string `json:"comment,omitempty"`
}

// ServiceInfo describes a service.
type ServiceInfo struct {
	Name    string       `json:"name"`
	File    string       `json:"file,omitempty"`
	Methods []MethodInfo `json:"methods"`
	Comment string       `json:"comment,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// FieldInfo describes a message field.
type FieldInfo struct {
	Name     string `json:"name"`
	JSONName string `json:"json_name"`
	Number   int    `json:"number"`
	Type     string `json:"type"`
	Label    string `json:"label,omitempty"` // repeated | optional | required | map
	MapKey   string `json:"map_key,omitempty"`
	MapValue string `json:"map_value,omitempty"`
	Oneof    string `json:"oneof,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// MessageInfo describes a message type.
type MessageInfo struct {
	Name     string      `json:"name"`
	File     string      `json:"file,omitempty"`
	Fields   []FieldInfo `json:"fields"`
	Oneofs   []string    `json:"oneofs,omitempty"`
	Nested   []string    `json:"nested_types,omitempty"`
	Comment  string      `json:"comment,omitempty"`
	MapEntry bool        `json:"-"`
}

// EnumValueInfo is one enum value.
type EnumValueInfo struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}

// EnumInfo describes an enum type.
type EnumInfo struct {
	Name    string          `json:"name"`
	File    string          `json:"file,omitempty"`
	Values  []EnumValueInfo `json:"values"`
	Comment string          `json:"comment,omitempty"`
}

// MethodKind returns unary | server_streaming | client_streaming | bidi_streaming.
func MethodKind(md protoreflect.MethodDescriptor) string {
	switch {
	case md.IsStreamingClient() && md.IsStreamingServer():
		return "bidi_streaming"
	case md.IsStreamingClient():
		return "client_streaming"
	case md.IsStreamingServer():
		return "server_streaming"
	default:
		return "unary"
	}
}

func comment(d protoreflect.Descriptor) string {
	f := d.ParentFile()
	if f == nil {
		return ""
	}
	loc := f.SourceLocations().ByDescriptor(d)
	return strings.TrimSpace(loc.LeadingComments)
}

// DescribeMethod returns structured method info.
func DescribeMethod(md protoreflect.MethodDescriptor) MethodInfo {
	return MethodInfo{
		Name:            string(md.Name()),
		FullName:        string(md.FullName()),
		Path:            FullMethod(md),
		InputType:       string(md.Input().FullName()),
		OutputType:      string(md.Output().FullName()),
		ClientStreaming: md.IsStreamingClient(),
		ServerStreaming: md.IsStreamingServer(),
		Kind:            MethodKind(md),
		Comment:         comment(md),
	}
}

// DescribeService returns structured service info.
func DescribeService(sd protoreflect.ServiceDescriptor) ServiceInfo {
	si := ServiceInfo{Name: string(sd.FullName()), Methods: []MethodInfo{}, Comment: comment(sd)}
	if f := sd.ParentFile(); f != nil {
		si.File = f.Path()
	}
	for i := 0; i < sd.Methods().Len(); i++ {
		si.Methods = append(si.Methods, DescribeMethod(sd.Methods().Get(i)))
	}
	return si
}

// fieldType names a field's type: scalar kind or message/enum full name.
func fieldType(fd protoreflect.FieldDescriptor) string {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return string(fd.Message().FullName())
	case protoreflect.EnumKind:
		return string(fd.Enum().FullName())
	default:
		return fd.Kind().String()
	}
}

// DescribeMessage returns structured message info.
func DescribeMessage(md protoreflect.MessageDescriptor) MessageInfo {
	mi := MessageInfo{Name: string(md.FullName()), Fields: []FieldInfo{}, Comment: comment(md), MapEntry: md.IsMapEntry()}
	if f := md.ParentFile(); f != nil {
		mi.File = f.Path()
	}
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		fi := FieldInfo{
			Name:     string(fd.Name()),
			JSONName: fd.JSONName(),
			Number:   int(fd.Number()),
			Type:     fieldType(fd),
			Comment:  comment(fd),
		}
		switch {
		case fd.IsMap():
			fi.Label = "map"
			fi.MapKey = fieldType(fd.MapKey())
			fi.MapValue = fieldType(fd.MapValue())
			fi.Type = fmt.Sprintf("map<%s, %s>", fi.MapKey, fi.MapValue)
		case fd.IsList():
			fi.Label = "repeated"
		case fd.Cardinality() == protoreflect.Required:
			fi.Label = "required"
		case fd.HasPresence() && fd.ContainingOneof() == nil && fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind:
			fi.Label = "optional"
		}
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			fi.Oneof = string(od.Name())
		}
		mi.Fields = append(mi.Fields, fi)
	}
	for i := 0; i < md.Oneofs().Len(); i++ {
		if od := md.Oneofs().Get(i); !od.IsSynthetic() {
			mi.Oneofs = append(mi.Oneofs, string(od.Name()))
		}
	}
	for i := 0; i < md.Messages().Len(); i++ {
		if n := md.Messages().Get(i); !n.IsMapEntry() {
			mi.Nested = append(mi.Nested, string(n.FullName()))
		}
	}
	for i := 0; i < md.Enums().Len(); i++ {
		mi.Nested = append(mi.Nested, string(md.Enums().Get(i).FullName()))
	}
	return mi
}

// DescribeEnum returns structured enum info.
func DescribeEnum(ed protoreflect.EnumDescriptor) EnumInfo {
	ei := EnumInfo{Name: string(ed.FullName()), Values: []EnumValueInfo{}, Comment: comment(ed)}
	if f := ed.ParentFile(); f != nil {
		ei.File = f.Path()
	}
	for i := 0; i < ed.Values().Len(); i++ {
		v := ed.Values().Get(i)
		ei.Values = append(ei.Values, EnumValueInfo{Name: string(v.Name()), Number: int(v.Number())})
	}
	return ei
}

// ProtoText renders a descriptor as readable proto-like source.
func ProtoText(d protoreflect.Descriptor) string {
	var b strings.Builder
	switch v := d.(type) {
	case protoreflect.ServiceDescriptor:
		writeService(&b, v)
	case protoreflect.MethodDescriptor:
		writeComment(&b, v, "")
		b.WriteString(methodLine(v))
		b.WriteString("\n")
	case protoreflect.MessageDescriptor:
		writeMessage(&b, v, "")
	case protoreflect.EnumDescriptor:
		writeEnum(&b, v, "")
	case protoreflect.FieldDescriptor:
		writeComment(&b, v, "")
		b.WriteString(fieldLine(v))
		b.WriteString("\n")
	case protoreflect.EnumValueDescriptor:
		fmt.Fprintf(&b, "%s = %d;\n", v.Name(), v.Number())
	case protoreflect.FileDescriptor:
		fmt.Fprintf(&b, "// file %s\npackage %s;\n", v.Path(), v.Package())
	default:
		fmt.Fprintf(&b, "%s\n", d.FullName())
	}
	return b.String()
}

func writeComment(b *strings.Builder, d protoreflect.Descriptor, indent string) {
	c := comment(d)
	if c == "" {
		return
	}
	for _, line := range strings.Split(c, "\n") {
		b.WriteString(indent)
		b.WriteString("//")
		if line != "" {
			b.WriteString(" ")
			b.WriteString(strings.TrimRight(line, " "))
		}
		b.WriteString("\n")
	}
}

func methodLine(md protoreflect.MethodDescriptor) string {
	in, out := string(md.Input().FullName()), string(md.Output().FullName())
	if md.IsStreamingClient() {
		in = "stream " + in
	}
	if md.IsStreamingServer() {
		out = "stream " + out
	}
	return fmt.Sprintf("rpc %s(%s) returns (%s);", md.Name(), in, out)
}

func writeService(b *strings.Builder, sd protoreflect.ServiceDescriptor) {
	writeComment(b, sd, "")
	fmt.Fprintf(b, "service %s {\n", sd.FullName())
	for i := 0; i < sd.Methods().Len(); i++ {
		md := sd.Methods().Get(i)
		writeComment(b, md, "  ")
		b.WriteString("  ")
		b.WriteString(methodLine(md))
		b.WriteString("\n")
	}
	b.WriteString("}\n")
}

func fieldLine(fd protoreflect.FieldDescriptor) string {
	var t string
	switch {
	case fd.IsMap():
		t = fmt.Sprintf("map<%s, %s>", fieldType(fd.MapKey()), fieldType(fd.MapValue()))
	case fd.IsList():
		t = "repeated " + fieldType(fd)
	case fd.Cardinality() == protoreflect.Required:
		t = "required " + fieldType(fd)
	case fd.HasPresence() && (fd.ContainingOneof() == nil || fd.ContainingOneof().IsSynthetic()) &&
		fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind:
		t = "optional " + fieldType(fd)
	default:
		t = fieldType(fd)
	}
	return fmt.Sprintf("%s %s = %d;", t, fd.Name(), fd.Number())
}

func writeMessage(b *strings.Builder, md protoreflect.MessageDescriptor, indent string) {
	writeComment(b, md, indent)
	fmt.Fprintf(b, "%smessage %s {\n", indent, nameFor(md, indent))
	inner := indent + "  "
	fields := md.Fields()
	done := map[protoreflect.Name]bool{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		od := fd.ContainingOneof()
		if od != nil && !od.IsSynthetic() {
			if done[od.Name()] {
				continue
			}
			done[od.Name()] = true
			fmt.Fprintf(b, "%soneof %s {\n", inner, od.Name())
			for j := 0; j < od.Fields().Len(); j++ {
				of := od.Fields().Get(j)
				writeComment(b, of, inner+"  ")
				fmt.Fprintf(b, "%s  %s\n", inner, fieldLine(of))
			}
			fmt.Fprintf(b, "%s}\n", inner)
			continue
		}
		writeComment(b, fd, inner)
		fmt.Fprintf(b, "%s%s\n", inner, fieldLine(fd))
	}
	for i := 0; i < md.Messages().Len(); i++ {
		if n := md.Messages().Get(i); !n.IsMapEntry() {
			writeMessage(b, n, inner)
		}
	}
	for i := 0; i < md.Enums().Len(); i++ {
		writeEnum(b, md.Enums().Get(i), inner)
	}
	fmt.Fprintf(b, "%s}\n", indent)
}

func writeEnum(b *strings.Builder, ed protoreflect.EnumDescriptor, indent string) {
	writeComment(b, ed, indent)
	fmt.Fprintf(b, "%senum %s {\n", indent, nameFor(ed, indent))
	for i := 0; i < ed.Values().Len(); i++ {
		v := ed.Values().Get(i)
		writeComment(b, v, indent+"  ")
		fmt.Fprintf(b, "%s  %s = %d;\n", indent, v.Name(), v.Number())
	}
	fmt.Fprintf(b, "%s}\n", indent)
}

// nameFor uses the full name at top level and the short name when nested.
func nameFor(d protoreflect.Descriptor, indent string) string {
	if indent == "" {
		return string(d.FullName())
	}
	return string(d.Name())
}

// Template returns an example JSON value for a message (fields set to
// zero-ish placeholders), to show the model what a request looks like.
func Template(md protoreflect.MessageDescriptor) any {
	return template(md, 0, map[protoreflect.FullName]bool{})
}

func template(md protoreflect.MessageDescriptor, depth int, stack map[protoreflect.FullName]bool) any {
	switch md.FullName() {
	case "google.protobuf.Timestamp":
		return "1970-01-01T00:00:00Z"
	case "google.protobuf.Duration":
		return "0s"
	case "google.protobuf.Struct", "google.protobuf.Value":
		return map[string]any{}
	case "google.protobuf.ListValue":
		return []any{}
	case "google.protobuf.FieldMask":
		return ""
	case "google.protobuf.Any":
		return map[string]any{"@type": "type.googleapis.com/package.Type"}
	case "google.protobuf.StringValue", "google.protobuf.BytesValue":
		return ""
	case "google.protobuf.BoolValue":
		return false
	case "google.protobuf.Int32Value", "google.protobuf.UInt32Value", "google.protobuf.DoubleValue", "google.protobuf.FloatValue":
		return 0
	case "google.protobuf.Int64Value", "google.protobuf.UInt64Value":
		return "0"
	}
	if depth > 4 || stack[md.FullName()] {
		return map[string]any{}
	}
	stack[md.FullName()] = true
	defer delete(stack, md.FullName())
	out := map[string]any{}
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		var v any
		if fd.IsMap() {
			v = map[string]any{}
		} else {
			v = scalarTemplate(fd, depth, stack)
			if fd.IsList() {
				v = []any{v}
			}
		}
		out[fd.JSONName()] = v
	}
	return out
}

func scalarTemplate(fd protoreflect.FieldDescriptor, depth int, stack map[protoreflect.FullName]bool) any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return false
	case protoreflect.StringKind:
		return ""
	case protoreflect.BytesKind:
		return "<base64 or {\"$file\": \"path\"}>"
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return "0"
	case protoreflect.EnumKind:
		if vals := fd.Enum().Values(); vals.Len() > 0 {
			return string(vals.Get(0).Name())
		}
		return 0
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return template(fd.Message(), depth+1, stack)
	default:
		return 0
	}
}

func kindOf(d protoreflect.Descriptor) string {
	switch d.(type) {
	case protoreflect.ServiceDescriptor:
		return "service"
	case protoreflect.MethodDescriptor:
		return "method"
	case protoreflect.MessageDescriptor:
		return "message"
	case protoreflect.EnumDescriptor:
		return "enum"
	case protoreflect.EnumValueDescriptor:
		return "enum value"
	case protoreflect.FieldDescriptor:
		return "field"
	case protoreflect.OneofDescriptor:
		return "oneof"
	case protoreflect.FileDescriptor:
		return "file"
	default:
		return "descriptor"
	}
}

// KindOf names the kind of a descriptor.
func KindOf(d protoreflect.Descriptor) string { return kindOf(d) }
