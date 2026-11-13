package rpcx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// XML-RPC typed values: a JSON object {"$type": "...", "value": ...} forces
// the XML-RPC type of a value. Decoded base64 and dateTime values are
// returned in the same form so they round-trip.
const (
	TypeKey  = "$type"
	ValueKey = "value"
)

// XMLRPCOptions control encoding.
type XMLRPCOptions struct {
	// AllowNil encodes JSON null as the <nil/> extension. When false, null is
	// an error.
	AllowNil bool
}

// Fault is an XML-RPC fault.
type Fault struct {
	FaultCode   any    `json:"faultCode"`
	FaultString string `json:"faultString"`
}

// XMLRPCResponse is a decoded methodResponse.
type XMLRPCResponse struct {
	Params []any
	Fault  *Fault
}

// EncodeCall builds a methodCall document.
func EncodeCall(method string, params []any, opts XMLRPCOptions) ([]byte, error) {
	if strings.TrimSpace(method) == "" {
		return nil, errors.New("method is required")
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString("\n<methodCall><methodName>")
	xml.EscapeText(&b, []byte(method))
	b.WriteString("</methodName><params>")
	for i, p := range params {
		b.WriteString("<param>")
		if err := encodeValue(&b, p, opts, fmt.Sprintf("params[%d]", i)); err != nil {
			return nil, err
		}
		b.WriteString("</param>")
	}
	b.WriteString("</params></methodCall>\n")
	return b.Bytes(), nil
}

func esc(b *bytes.Buffer, s string) { xml.EscapeText(b, []byte(s)) }

func encodeValue(b *bytes.Buffer, v any, opts XMLRPCOptions, path string) error {
	b.WriteString("<value>")
	defer b.WriteString("</value>")
	switch x := v.(type) {
	case nil:
		if !opts.AllowNil {
			return fmt.Errorf("%s: null is not valid XML-RPC (set allow_nil=true to send the <nil/> extension)", path)
		}
		b.WriteString("<nil/>")
	case bool:
		if x {
			b.WriteString("<boolean>1</boolean>")
		} else {
			b.WriteString("<boolean>0</boolean>")
		}
	case string:
		b.WriteString("<string>")
		esc(b, x)
		b.WriteString("</string>")
	case int:
		return encodeInt(b, int64(x))
	case int32:
		return encodeInt(b, int64(x))
	case int64:
		return encodeInt(b, x)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return encodeInt(b, i)
		}
		f, err := x.Float64()
		if err != nil {
			return fmt.Errorf("%s: invalid number %q", path, x)
		}
		return encodeDouble(b, f, path)
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return encodeInt(b, int64(x))
		}
		return encodeDouble(b, x, path)
	case float32:
		return encodeValueInner(b, float64(x), opts, path)
	case []any:
		b.WriteString("<array><data>")
		for i, e := range x {
			if err := encodeValue(b, e, opts, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		b.WriteString("</data></array>")
	case map[string]any:
		if t, ok := x[TypeKey]; ok {
			ts, _ := t.(string)
			return encodeTyped(b, ts, x[ValueKey], opts, path)
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("<struct>")
		for _, k := range keys {
			b.WriteString("<member><name>")
			esc(b, k)
			b.WriteString("</name>")
			if err := encodeValue(b, x[k], opts, path+"."+k); err != nil {
				return err
			}
			b.WriteString("</member>")
		}
		b.WriteString("</struct>")
	default:
		return fmt.Errorf("%s: unsupported value type %T", path, v)
	}
	return nil
}

// encodeValueInner writes the inside of an already-open <value>.
func encodeValueInner(b *bytes.Buffer, v any, opts XMLRPCOptions, path string) error {
	var tmp bytes.Buffer
	if err := encodeValue(&tmp, v, opts, path); err != nil {
		return err
	}
	s := tmp.String()
	b.WriteString(strings.TrimSuffix(strings.TrimPrefix(s, "<value>"), "</value>"))
	return nil
}

func encodeInt(b *bytes.Buffer, i int64) error {
	if i >= math.MinInt32 && i <= math.MaxInt32 {
		fmt.Fprintf(b, "<int>%d</int>", i)
	} else {
		fmt.Fprintf(b, "<i8>%d</i8>", i)
	}
	return nil
}

func encodeDouble(b *bytes.Buffer, f float64, path string) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("%s: NaN/Inf cannot be encoded as XML-RPC double", path)
	}
	b.WriteString("<double>")
	b.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
	b.WriteString("</double>")
	return nil
}

func encodeTyped(b *bytes.Buffer, typ string, v any, opts XMLRPCOptions, path string) error {
	switch typ {
	case "string":
		b.WriteString("<string>")
		esc(b, fmt.Sprint(stringish(v)))
		b.WriteString("</string>")
	case "int", "i4", "i8":
		i, err := toInt(v)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", path, typ, err)
		}
		if typ != "i8" && (i < math.MinInt32 || i > math.MaxInt32) {
			return fmt.Errorf("%s: %d does not fit in a 32-bit %s (use i8)", path, i, typ)
		}
		fmt.Fprintf(b, "<%s>%d</%s>", typ, i, typ)
	case "double":
		f, err := toFloat(v)
		if err != nil {
			return fmt.Errorf("%s: double: %w", path, err)
		}
		return encodeDouble(b, f, path)
	case "boolean", "bool":
		switch x := v.(type) {
		case bool:
			return encodeValueInner(b, x, opts, path)
		case string:
			bv, err := strconv.ParseBool(x)
			if err != nil {
				return fmt.Errorf("%s: boolean: %w", path, err)
			}
			return encodeValueInner(b, bv, opts, path)
		case float64:
			return encodeValueInner(b, x != 0, opts, path)
		}
		return fmt.Errorf("%s: boolean needs true/false", path)
	case "base64":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s: base64 value must be a base64 string", path)
		}
		raw, err := decodeB64(s)
		if err != nil {
			return fmt.Errorf("%s: base64: %w", path, err)
		}
		b.WriteString("<base64>")
		b.WriteString(base64.StdEncoding.EncodeToString(raw))
		b.WriteString("</base64>")
	case "dateTime.iso8601", "datetime", "dateTime":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s: dateTime.iso8601 value must be a string", path)
		}
		b.WriteString("<dateTime.iso8601>")
		esc(b, normaliseDateTime(s))
		b.WriteString("</dateTime.iso8601>")
	case "nil":
		b.WriteString("<nil/>")
	case "struct", "array":
		return encodeValueInner(b, v, opts, path)
	default:
		return fmt.Errorf("%s: unknown $type %q (use base64, dateTime.iso8601, i4, int, i8, double, string, boolean, nil)", path, typ)
	}
	return nil
}

func stringish(v any) any {
	if v == nil {
		return ""
	}
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return v
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		if x != math.Trunc(x) {
			return 0, fmt.Errorf("%v is not an integer", x)
		}
		return int64(x), nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case json.Number:
		return x.Int64()
	case string:
		return strconv.ParseInt(strings.TrimSpace(x), 10, 64)
	}
	return 0, fmt.Errorf("cannot convert %T to an integer", v)
}

func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case json.Number:
		return x.Float64()
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	}
	return 0, fmt.Errorf("cannot convert %T to a double", v)
}

func decodeB64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// normaliseDateTime converts RFC 3339 input to the classic XML-RPC form
// (19980717T14:08:55, local clock of the given offset); other strings are
// sent unchanged.
func normaliseDateTime(s string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("20060102T15:04:05")
		}
	}
	return s
}

// DecodeResponse parses a methodResponse document.
func DecodeResponse(r io.Reader) (*XMLRPCResponse, error) {
	d := xml.NewDecoder(r)
	d.Strict = false
	d.CharsetReader = func(label string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := expectStart(d, "methodResponse"); err != nil {
		return nil, err
	}
	out := &XMLRPCResponse{}
	for {
		tok, err := nextElem(d)
		if err != nil {
			return nil, fmt.Errorf("methodResponse: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			switch t.Name.Local {
			case "params":
				for {
					tok, err := nextElem(d)
					if err != nil {
						return nil, fmt.Errorf("params: %w", err)
					}
					if _, ok := tok.(xml.EndElement); ok {
						break
					}
					st := tok.(xml.StartElement)
					if st.Name.Local != "param" {
						return nil, fmt.Errorf("unexpected <%s> in <params>", st.Name.Local)
					}
					v, err := decodeParam(d)
					if err != nil {
						return nil, err
					}
					out.Params = append(out.Params, v)
				}
			case "fault":
				if err := expectStart(d, "value"); err != nil {
					return nil, fmt.Errorf("fault: %w", err)
				}
				v, err := decodeValueBody(d)
				if err != nil {
					return nil, fmt.Errorf("fault: %w", err)
				}
				f := &Fault{}
				if m, ok := v.(map[string]any); ok {
					f.FaultCode = m["faultCode"]
					if s, ok := m["faultString"].(string); ok {
						f.FaultString = s
					}
				} else {
					f.FaultString = fmt.Sprint(v)
				}
				out.Fault = f
				if err := d.Skip(); err != nil { // </fault>
					return nil, err
				}
			default:
				if err := d.Skip(); err != nil {
					return nil, err
				}
			}
		}
	}
}

// decodeParam reads <value>…</value></param> after <param>.
func decodeParam(d *xml.Decoder) (any, error) {
	if err := expectStart(d, "value"); err != nil {
		return nil, fmt.Errorf("param: %w", err)
	}
	v, err := decodeValueBody(d)
	if err != nil {
		return nil, err
	}
	return v, d.Skip() // </param>
}

// DecodeValue decodes a standalone <value> element (exported for tests and
// for callers that parse methodCall documents).
func DecodeValue(r io.Reader) (any, error) {
	d := xml.NewDecoder(r)
	if err := expectStart(d, "value"); err != nil {
		return nil, err
	}
	return decodeValueBody(d)
}

// decodeValueBody decodes the content of <value> up to and including </value>.
func decodeValueBody(d *xml.Decoder) (any, error) {
	var text strings.Builder
	var result any
	typed := false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("value: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if !typed {
				text.Write(t)
			}
		case xml.StartElement:
			if typed {
				return nil, fmt.Errorf("value: more than one type element")
			}
			typed = true
			v, err := decodeTyped(d, t)
			if err != nil {
				return nil, err
			}
			result = v
		case xml.EndElement:
			if !typed {
				// No type element: the default type is string.
				return text.String(), nil
			}
			return result, nil
		}
	}
}

func decodeTyped(d *xml.Decoder, st xml.StartElement) (any, error) {
	name := st.Name.Local
	switch name {
	case "struct":
		m := map[string]any{}
		for {
			tok, err := nextElem(d)
			if err != nil {
				return nil, fmt.Errorf("struct: %w", err)
			}
			if _, ok := tok.(xml.EndElement); ok {
				return m, nil
			}
			if tok.(xml.StartElement).Name.Local != "member" {
				return nil, fmt.Errorf("struct: unexpected <%s>", tok.(xml.StartElement).Name.Local)
			}
			var key string
			var val any
			haveVal := false
			for {
				tok, err := nextElem(d)
				if err != nil {
					return nil, fmt.Errorf("member: %w", err)
				}
				if _, ok := tok.(xml.EndElement); ok {
					break
				}
				se := tok.(xml.StartElement)
				switch se.Name.Local {
				case "name":
					s, err := readText(d)
					if err != nil {
						return nil, err
					}
					key = s
				case "value":
					v, err := decodeValueBody(d)
					if err != nil {
						return nil, err
					}
					val, haveVal = v, true
				default:
					if err := d.Skip(); err != nil {
						return nil, err
					}
				}
			}
			if haveVal {
				m[key] = val
			}
		}
	case "array":
		arr := []any{}
		if err := expectStart(d, "data"); err != nil {
			return nil, fmt.Errorf("array: %w", err)
		}
		for {
			tok, err := nextElem(d)
			if err != nil {
				return nil, fmt.Errorf("array: %w", err)
			}
			if _, ok := tok.(xml.EndElement); ok { // </data>
				break
			}
			if tok.(xml.StartElement).Name.Local != "value" {
				return nil, fmt.Errorf("array: unexpected <%s>", tok.(xml.StartElement).Name.Local)
			}
			v, err := decodeValueBody(d)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if err := d.Skip(); err != nil { // </array>
			return nil, err
		}
		return arr, nil
	case "nil":
		return nil, d.Skip()
	}
	s, err := readText(d)
	if err != nil {
		return nil, err
	}
	switch name {
	case "string":
		return s, nil
	case "int", "i4", "i8", "i2", "i1":
		i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("<%s>: %w", name, err)
		}
		return i, nil
	case "boolean":
		switch strings.TrimSpace(s) {
		case "1", "true":
			return true, nil
		case "0", "false":
			return false, nil
		}
		return nil, fmt.Errorf("<boolean>: invalid value %q", s)
	case "double", "float":
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("<double>: %w", err)
		}
		return f, nil
	case "base64":
		return map[string]any{TypeKey: "base64", ValueKey: strings.Join(strings.Fields(s), "")}, nil
	case "dateTime.iso8601":
		return map[string]any{TypeKey: "dateTime.iso8601", ValueKey: strings.TrimSpace(s)}, nil
	}
	// Unknown extension type: keep it typed.
	return map[string]any{TypeKey: name, ValueKey: s}, nil
}

// readText reads character data up to the end of the current element.
func readText(d *xml.Decoder) (string, error) {
	var sb strings.Builder
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return sb.String(), nil
			}
			depth--
		}
	}
}

// nextElem returns the next start or end element, skipping text, comments
// and processing instructions.
func nextElem(d *xml.Decoder) (xml.Token, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			return t, nil
		}
	}
}

func expectStart(d *xml.Decoder, name string) error {
	tok, err := nextElem(d)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("expected <%s>, got end of document", name)
		}
		return err
	}
	st, ok := tok.(xml.StartElement)
	if !ok || st.Name.Local != name {
		return fmt.Errorf("expected <%s>", name)
	}
	return nil
}
