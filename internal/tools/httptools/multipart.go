package httptools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type multipartPart struct {
	Name        string            `json:"name" jsonschema:"form field name (repeat the name to send several files in one field)"`
	Value       *string           `json:"value,omitempty" jsonschema:"text value (a plain text field)"`
	JSON        any               `json:"json,omitempty" jsonschema:"JSON value sent as an application/json part"`
	File        string            `json:"file,omitempty" jsonschema:"stream this file as the part content (inside an allowed read directory)"`
	Base64      string            `json:"base64,omitempty" jsonschema:"binary part content as base64 (small payloads only)"`
	Filename    string            `json:"filename,omitempty" jsonschema:"filename sent with the part (default: the file's base name; base64 parts have none unless set)"`
	ContentType string            `json:"content_type,omitempty" jsonschema:"part Content-Type (default: detected for files, application/octet-stream for base64)"`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"extra part headers"`
}

type multipartIn struct {
	Method         string            `json:"method,omitempty" jsonschema:"HTTP method (default POST)"`
	URL            string            `json:"url" jsonschema:"absolute http:// or https:// URL"`
	Fields         any               `json:"fields,omitempty" jsonschema:"text fields sent first: a list of {name, value} objects or an object mapping name to a string or list of strings"`
	Parts          []multipartPart   `json:"parts,omitempty" jsonschema:"parts in order: text (value), JSON (json), file (file streamed from disk) or binary (base64)"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"request headers (Content-Type is set automatically)"`
	Query          map[string]any    `json:"query,omitempty" jsonschema:"query parameters appended to the URL; each value is a string or a list of strings"`
	IncludeRequest bool              `json:"include_request,omitempty" jsonschema:"include a redacted echo of the request (part names, file sizes and hashes; never file contents)"`
	DownloadOptions
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"authentication"`
}

func handleMultipart(d *tools.Deps) tools.Handler[multipartIn] {
	return func(ctx context.Context, mreq *mcp.CallToolRequest, in multipartIn) (any, error) {
		u, err := buildURL(in.URL, in.Query)
		if err != nil {
			return nil, err
		}
		method, err := normalizeMethod(in.Method, "POST")
		if err != nil {
			return nil, err
		}
		fields, err := parseFields(in.Fields)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 && len(in.Parts) == 0 {
			return nil, errors.New("give at least one field or part")
		}
		body, err := buildMultipart(d, fields, in.Parts)
		if err != nil {
			return nil, err
		}
		headers := map[string]string{}
		for k, v := range in.Headers {
			if strings.EqualFold(k, "Content-Type") {
				continue // the boundary must match the body
			}
			headers[k] = v
		}
		return send(ctx, mreq, d, sendSpec{
			method:         method,
			url:            u,
			headers:        headers,
			body:           body,
			download:       in.DownloadOptions,
			includeRequest: in.IncludeRequest,
			opts:           in.HTTPOptions,
			auth:           in.Auth,
		})
	}
}

// segment is a piece of a multipart body: framing bytes or a file.
type segment struct {
	data []byte
	file *fileBody
}

// buildMultipart lays out the multipart body as framing bytes plus file
// segments. File contents are streamed when the body is read, so the total
// size (and Content-Length) is known without buffering any file.
func buildMultipart(d *tools.Deps, fields []nameValue, parts []multipartPart) (*bodySource, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	var segs []segment
	var files []*fileBody
	flush := func() {
		if buf.Len() > 0 {
			segs = append(segs, segment{data: append([]byte(nil), buf.Bytes()...)})
			buf.Reset()
		}
	}
	var inline int64
	maxInline := d.Cfg.MaxInlineBase64Bytes
	for _, f := range fields {
		w, err := mw.CreatePart(partHeader(f.Name, "", false, "", nil))
		if err != nil {
			return nil, err
		}
		io.WriteString(w, f.Value)
	}
	for i, p := range parts {
		if p.Name == "" {
			return nil, fmt.Errorf("parts[%d]: name is required", i)
		}
		n := 0
		for _, set := range []bool{p.Value != nil, p.JSON != nil, p.File != "", p.Base64 != ""} {
			if set {
				n++
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("parts[%d] %q: set exactly one of value, json, file, base64", i, p.Name)
		}
		switch {
		case p.Value != nil:
			w, err := mw.CreatePart(partHeader(p.Name, p.Filename, p.Filename != "", p.ContentType, p.Headers))
			if err != nil {
				return nil, err
			}
			io.WriteString(w, *p.Value)
		case p.JSON != nil:
			b, err := json.Marshal(p.JSON)
			if err != nil {
				return nil, fmt.Errorf("parts[%d] %q json: %w", i, p.Name, err)
			}
			ct := p.ContentType
			if ct == "" {
				ct = "application/json"
			}
			w, err := mw.CreatePart(partHeader(p.Name, p.Filename, p.Filename != "", ct, p.Headers))
			if err != nil {
				return nil, err
			}
			w.Write(b)
		case p.Base64 != "":
			b, err := types.DecodeBase64(p.Base64)
			if err != nil {
				return nil, fmt.Errorf("parts[%d] %q base64: %w", i, p.Name, err)
			}
			inline += int64(len(b))
			if maxInline > 0 && inline > maxInline {
				return nil, fmt.Errorf("inline base64 parts exceed %d bytes; put the data in files and use file parts", maxInline)
			}
			ct := p.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			w, err := mw.CreatePart(partHeader(p.Name, p.Filename, p.Filename != "", ct, p.Headers))
			if err != nil {
				return nil, err
			}
			w.Write(b)
		default:
			fb, err := newFileBody(d.Files, p.File, d.Cfg.UploadBytes(0))
			if err != nil {
				return nil, fmt.Errorf("parts[%d] %q: %w", i, p.Name, err)
			}
			name := p.Filename
			if name == "" {
				name = fb.info.Name
			}
			ct := p.ContentType
			if ct == "" {
				ct = fb.info.ContentType
			}
			if _, err := mw.CreatePart(partHeader(p.Name, name, true, ct, p.Headers)); err != nil {
				return nil, err
			}
			flush()
			segs = append(segs, segment{file: fb})
			files = append(files, fb)
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	flush()

	var size int64
	for _, s := range segs {
		if s.file != nil {
			size += s.file.info.SizeBytes
		} else {
			size += int64(len(s.data))
		}
	}
	ct := mw.FormDataContentType()
	sum := &bodySummary{Kind: "multipart", SizeBytes: size, ContentType: ct}
	return &bodySource{
		open:        func() (io.ReadCloser, error) { return &segReader{segs: segs}, nil },
		size:        size,
		contentType: ct,
		summary:     sum,
		finish: func() []types.FileInfo {
			var out []types.FileInfo
			for _, fb := range files {
				out = append(out, fb.Info())
			}
			sum.Files = out
			return out
		},
	}, nil
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"", "\r", "%0D", "\n", "%0A")

// partHeader builds the MIME header of one part.
func partHeader(name, filename string, withFilename bool, contentType string, extra map[string]string) textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	cd := fmt.Sprintf(`form-data; name="%s"`, quoteEscaper.Replace(name))
	if withFilename {
		cd += fmt.Sprintf(`; filename="%s"`, quoteEscaper.Replace(filename))
	}
	h.Set("Content-Disposition", cd)
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Content-Disposition") {
			continue
		}
		h.Set(k, extra[k])
	}
	return h
}

// segReader streams segments in order, opening files lazily.
type segReader struct {
	segs []segment
	i    int
	cur  io.ReadCloser
}

func (r *segReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.i >= len(r.segs) {
				return 0, io.EOF
			}
			s := r.segs[r.i]
			r.i++
			if s.file != nil {
				rc, err := s.file.Open()
				if err != nil {
					return 0, err
				}
				r.cur = rc
			} else {
				r.cur = io.NopCloser(bytes.NewReader(s.data))
			}
		}
		n, err := r.cur.Read(p)
		if err == io.EOF {
			r.cur.Close()
			r.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (r *segReader) Close() error {
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}
