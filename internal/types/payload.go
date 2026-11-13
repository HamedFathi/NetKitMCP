package types

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
)

// ResolvedPayload is a payload ready to send. Exactly one of Data / Reader is
// set. Reader-backed payloads must be closed.
type ResolvedPayload struct {
	Data        []byte
	Reader      io.ReadCloser
	Size        int64 // -1 when unknown
	ContentType string
	File        *FileInfo // set for file payloads (without hash until streamed)
}

// Close closes the underlying reader if any.
func (r *ResolvedPayload) Close() error {
	if r != nil && r.Reader != nil {
		return r.Reader.Close()
	}
	return nil
}

// Open returns a reader over the payload regardless of its backing.
func (r *ResolvedPayload) Open() io.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return bytes.NewReader(r.Data)
}

// Bytes returns the payload fully in memory, reading files up to maxBytes.
func (r *ResolvedPayload) Bytes(maxBytes int64) ([]byte, error) {
	if r.Reader == nil {
		return r.Data, nil
	}
	defer r.Reader.Close()
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	data, err := io.ReadAll(io.LimitReader(r.Reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("payload exceeds %d bytes; it cannot be buffered in memory for this protocol", maxBytes)
	}
	return data, nil
}

// Resolve turns a Payload into bytes or a file stream. maxBase64 limits the
// decoded size of inline base64; maxFile limits file size (0 = unlimited).
func (p *Payload) Resolve(files *fileio.Policy, maxBase64, maxFile int64) (*ResolvedPayload, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	switch {
	case p == nil || p.IsZero():
		return &ResolvedPayload{Data: nil, Size: 0}, nil
	case p.Text != nil:
		return &ResolvedPayload{Data: []byte(*p.Text), Size: int64(len(*p.Text)), ContentType: "text/plain; charset=utf-8"}, nil
	case p.JSON != nil:
		b, err := json.Marshal(p.JSON)
		if err != nil {
			return nil, fmt.Errorf("payload json: %w", err)
		}
		return &ResolvedPayload{Data: b, Size: int64(len(b)), ContentType: "application/json"}, nil
	case p.Base64 != "":
		b, err := DecodeBase64(p.Base64)
		if err != nil {
			return nil, fmt.Errorf("payload base64: %w", err)
		}
		if maxBase64 > 0 && int64(len(b)) > maxBase64 {
			return nil, fmt.Errorf("inline base64 payload is %d bytes, above the %d byte limit; use a file instead", len(b), maxBase64)
		}
		return &ResolvedPayload{Data: b, Size: int64(len(b)), ContentType: "application/octet-stream"}, nil
	default:
		f, st, err := files.OpenRead(p.File, maxFile)
		if err != nil {
			return nil, err
		}
		ct := fileio.DetectContentType(f.Name(), nil)
		return &ResolvedPayload{
			Reader:      f,
			Size:        st.Size(),
			ContentType: ct,
			File:        &FileInfo{Name: st.Name(), Path: f.Name(), SizeBytes: st.Size(), ContentType: ct},
		}, nil
	}
}

// DecodeBase64 accepts standard or URL-safe base64, padded or not.
func DecodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}
