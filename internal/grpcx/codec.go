package grpcx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	// Register google.rpc error detail types so status details decode.
	_ "google.golang.org/genproto/googleapis/rpc/errdetails"
)

// TypeResolver resolves message and extension types for protojson.
type TypeResolver interface {
	protoregistry.MessageTypeResolver
	protoregistry.ExtensionTypeResolver
}

// resolver looks types up in the dynamic registry first, then in the
// process-global registry (well-known types, google.rpc error details).
type resolver struct {
	dyn *dynamicpb.Types
}

// NewResolver returns a resolver over files (which may keep growing, e.g.
// with lazily loaded reflection descriptors). files may be nil.
func NewResolver(files *protoregistry.Files) TypeResolver {
	if files == nil {
		files = new(protoregistry.Files)
	}
	return &resolver{dyn: dynamicpb.NewTypes(files)}
}

func (r *resolver) FindMessageByName(n protoreflect.FullName) (protoreflect.MessageType, error) {
	if mt, err := r.dyn.FindMessageByName(n); err == nil {
		return mt, nil
	}
	return protoregistry.GlobalTypes.FindMessageByName(n)
}

func (r *resolver) FindMessageByURL(u string) (protoreflect.MessageType, error) {
	if mt, err := r.dyn.FindMessageByURL(u); err == nil {
		return mt, nil
	}
	return protoregistry.GlobalTypes.FindMessageByURL(u)
}

func (r *resolver) FindExtensionByName(n protoreflect.FullName) (protoreflect.ExtensionType, error) {
	if xt, err := r.dyn.FindExtensionByName(n); err == nil {
		return xt, nil
	}
	return protoregistry.GlobalTypes.FindExtensionByName(n)
}

func (r *resolver) FindExtensionByNumber(m protoreflect.FullName, f protoreflect.FieldNumber) (protoreflect.ExtensionType, error) {
	if xt, err := r.dyn.FindExtensionByNumber(m, f); err == nil {
		return xt, nil
	}
	return protoregistry.GlobalTypes.FindExtensionByNumber(m, f)
}

// FileLoader reads a file referenced by {"$file": "path"} in a bytes field.
type FileLoader func(path string) ([]byte, error)

// Codec converts between JSON and dynamic protobuf messages.
type Codec struct {
	Resolver      TypeResolver
	LoadFile      FileLoader
	EmitDefaults  bool
	UseProtoNames bool
}

// NewCodec returns a codec over files.
func NewCodec(files *protoregistry.Files, load FileLoader) *Codec {
	return &Codec{Resolver: NewResolver(files), LoadFile: load}
}

// NewMessage builds a message of type md from a JSON value. v may be nil
// (empty message), a decoded JSON value (map[string]any, ...), or a string
// holding JSON. bytes fields accept base64 or {"$file": "path"}.
func (c *Codec) NewMessage(md protoreflect.MessageDescriptor, v any) (*dynamicpb.Message, error) {
	msg := dynamicpb.NewMessage(md)
	if v == nil {
		return msg, nil
	}
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return msg, nil
		}
		var parsed any
		if err := json.Unmarshal([]byte(s), &parsed); err != nil {
			return nil, fmt.Errorf("request for %s: expected a JSON object: %w", md.FullName(), err)
		}
		v = parsed
	}
	prepared, err := c.prepareMessage(v, md, 0)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(prepared)
	if err != nil {
		return nil, err
	}
	uo := protojson.UnmarshalOptions{Resolver: c.Resolver}
	if err := uo.Unmarshal(b, msg); err != nil {
		return nil, fmt.Errorf("request does not match %s: %w", md.FullName(), err)
	}
	return msg, nil
}

// ToJSON renders a message as compact JSON.
func (c *Codec) ToJSON(m proto.Message) (json.RawMessage, error) {
	mo := protojson.MarshalOptions{Resolver: c.Resolver, EmitUnpopulated: c.EmitDefaults, UseProtoNames: c.UseProtoNames}
	b, err := mo.Marshal(m)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return b, nil
	}
	return buf.Bytes(), nil
}

// Unmarshal decodes binary protobuf into a new message of type md and
// renders it as JSON.
func (c *Codec) Unmarshal(md protoreflect.MessageDescriptor, data []byte) (json.RawMessage, error) {
	msg := dynamicpb.NewMessage(md)
	uo := proto.UnmarshalOptions{Resolver: c.Resolver}
	if err := uo.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("decode %s: %w", md.FullName(), err)
	}
	return c.ToJSON(msg)
}

// NormalizeJSON decodes protojson into a message of type md and re-renders
// it (normalising names and applying EmitDefaults).
func (c *Codec) NormalizeJSON(md protoreflect.MessageDescriptor, data []byte) (json.RawMessage, error) {
	msg := dynamicpb.NewMessage(md)
	uo := protojson.UnmarshalOptions{Resolver: c.Resolver, DiscardUnknown: true}
	if err := uo.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("decode %s: %w", md.FullName(), err)
	}
	return c.ToJSON(msg)
}

const maxPrepareDepth = 64

// wellKnownJSON are messages with a special JSON mapping that must not be
// walked field by field.
var wellKnownJSON = map[protoreflect.FullName]bool{
	"google.protobuf.Any": true, "google.protobuf.Struct": true, "google.protobuf.Value": true,
	"google.protobuf.ListValue": true, "google.protobuf.Timestamp": true, "google.protobuf.Duration": true,
	"google.protobuf.FieldMask": true, "google.protobuf.Empty": true, "google.protobuf.NullValue": true,
	"google.protobuf.DoubleValue": true, "google.protobuf.FloatValue": true, "google.protobuf.Int64Value": true,
	"google.protobuf.UInt64Value": true, "google.protobuf.Int32Value": true, "google.protobuf.UInt32Value": true,
	"google.protobuf.BoolValue": true, "google.protobuf.StringValue": true,
}

func (c *Codec) prepareMessage(v any, md protoreflect.MessageDescriptor, depth int) (any, error) {
	if depth > maxPrepareDepth {
		return v, nil
	}
	if md.FullName() == "google.protobuf.BytesValue" {
		return c.prepareBytes(v)
	}
	if wellKnownJSON[md.FullName()] {
		return v, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return v, nil
	}
	fields := md.Fields()
	for k, val := range obj {
		fd := fields.ByJSONName(k)
		if fd == nil {
			fd = fields.ByName(protoreflect.Name(k))
		}
		if fd == nil {
			continue
		}
		nv, err := c.prepareField(val, fd, depth)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		obj[k] = nv
	}
	return obj, nil
}

func (c *Codec) prepareField(v any, fd protoreflect.FieldDescriptor, depth int) (any, error) {
	switch {
	case fd.IsMap():
		m, ok := v.(map[string]any)
		if !ok {
			return v, nil
		}
		for k, val := range m {
			nv, err := c.prepareSingle(val, fd.MapValue(), depth)
			if err != nil {
				return nil, err
			}
			m[k] = nv
		}
		return m, nil
	case fd.IsList():
		arr, ok := v.([]any)
		if !ok {
			return v, nil
		}
		for i, val := range arr {
			nv, err := c.prepareSingle(val, fd, depth)
			if err != nil {
				return nil, err
			}
			arr[i] = nv
		}
		return arr, nil
	default:
		return c.prepareSingle(v, fd, depth)
	}
}

func (c *Codec) prepareSingle(v any, fd protoreflect.FieldDescriptor, depth int) (any, error) {
	switch fd.Kind() {
	case protoreflect.BytesKind:
		return c.prepareBytes(v)
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return c.prepareMessage(v, fd.Message(), depth+1)
	}
	return v, nil
}

// prepareBytes replaces {"$file": "path"} with the file's base64 contents.
func (c *Codec) prepareBytes(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return v, nil
	}
	p, ok := m["$file"].(string)
	if !ok || len(m) != 1 {
		return nil, fmt.Errorf(`bytes fields take a base64 string or {"$file": "path"}`)
	}
	if c.LoadFile == nil {
		return nil, fmt.Errorf("$file references are not available")
	}
	data, err := c.LoadFile(p)
	if err != nil {
		return nil, fmt.Errorf("$file %q: %w", p, err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
