// Package grpcweb implements gRPC-Web framing and a small gRPC-Web client.
//
// A frame is a 1-byte flag followed by a 4-byte big-endian length and the
// payload. Flag bit 0x80 marks the trailers frame, whose payload is an
// HTTP/1-style header block. The same envelope format (with flag 0x02 for
// the end-of-stream message) is used by the Connect streaming protocol, so
// package connectrpc reuses the framing helpers defined here.
package grpcweb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
)

// Frame flags.
const (
	FlagData       byte = 0x00
	FlagCompressed byte = 0x01
	FlagEndStream  byte = 0x02 // Connect end-of-stream message
	FlagTrailer    byte = 0x80 // gRPC-Web trailers frame
)

// HeaderLen is the size of the frame prefix.
const HeaderLen = 5

// DefaultMaxFrame bounds a single frame when the caller passes 0.
const DefaultMaxFrame = 16 << 20

// Frame is one length-prefixed message.
type Frame struct {
	Flag byte
	Data []byte
}

// IsTrailer reports whether the frame is a gRPC-Web trailers frame.
func (f Frame) IsTrailer() bool { return f.Flag&FlagTrailer != 0 }

// IsCompressed reports whether the payload is compressed.
func (f Frame) IsCompressed() bool { return f.Flag&FlagCompressed != 0 }

// IsEndStream reports whether the frame is a Connect end-of-stream message.
func (f Frame) IsEndStream() bool { return f.Flag&FlagEndStream != 0 }

// EncodeFrame returns the wire encoding of one frame.
func EncodeFrame(flag byte, data []byte) []byte {
	out := make([]byte, HeaderLen+len(data))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(data)))
	copy(out[HeaderLen:], data)
	return out
}

// WriteFrame writes one frame to w.
func WriteFrame(w io.Writer, flag byte, data []byte) error {
	var hdr [HeaderLen]byte
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ErrFrameTooLarge is returned when a frame exceeds the configured limit.
var ErrFrameTooLarge = errors.New("frame exceeds the maximum message size")

// ReadFrame reads one frame. It returns io.EOF only when the stream ends
// cleanly before a frame starts, and io.ErrUnexpectedEOF for a truncated frame.
func ReadFrame(r io.Reader, maxSize int) (Frame, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxFrame
	}
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if uint64(n) > uint64(maxSize) {
		return Frame{}, fmt.Errorf("%w: %d > %d bytes", ErrFrameTooLarge, n, maxSize)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{Flag: hdr[0], Data: data}, nil
}

// Decompress returns the frame payload, gunzipping it when the compressed
// flag is set. encoding is the negotiated message encoding (e.g. "gzip").
func Decompress(f Frame, encoding string, maxSize int) ([]byte, error) {
	if !f.IsCompressed() {
		return f.Data, nil
	}
	switch strings.ToLower(encoding) {
	case "gzip":
	case "", "identity":
		return nil, errors.New("compressed frame received but no message encoding was negotiated")
	default:
		return nil, fmt.Errorf("unsupported message encoding %q", encoding)
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxFrame
	}
	zr, err := gzip.NewReader(bytes.NewReader(f.Data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(maxSize)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxSize {
		return nil, ErrFrameTooLarge
	}
	return out, nil
}

// EncodeTrailers renders a trailers block ("key: value\r\n" lines, keys
// lower-cased and sorted for determinism).
func EncodeTrailers(h http.Header) []byte {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(strings.ToLower(k))
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return b.Bytes()
}

// ParseTrailers parses the payload of a trailers frame.
func ParseTrailers(data []byte) (http.Header, error) {
	h := http.Header{}
	// Ensure the block ends with a blank line for textproto.
	block := bytes.TrimRight(data, "\r\n")
	if len(block) == 0 {
		return h, nil
	}
	r := textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(block), strings.NewReader("\r\n\r\n"))))
	mh, err := r.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("parse trailers frame: %w", err)
	}
	for k, vs := range mh {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	return h, nil
}

// TextReader decodes a grpc-web-text response body. The body may be the
// concatenation of several independently padded base64 chunks, so it is
// decoded in 4-character quanta, skipping whitespace.
type TextReader struct {
	r    *bufio.Reader
	out  []byte
	quad [4]byte
	n    int
	err  error
}

// NewTextReader wraps r.
func NewTextReader(r io.Reader) *TextReader { return &TextReader{r: bufio.NewReader(r)} }

// Read implements io.Reader.
func (t *TextReader) Read(p []byte) (int, error) {
	for len(t.out) == 0 {
		if t.err != nil {
			return 0, t.err
		}
		c, err := t.r.ReadByte()
		if err != nil {
			if err == io.EOF && t.n != 0 {
				err = errors.New("grpc-web-text: truncated base64")
			}
			t.err = err
			continue
		}
		switch c {
		case ' ', '\r', '\n', '\t':
			continue
		}
		t.quad[t.n] = c
		t.n++
		if t.n == 4 {
			t.n = 0
			var dst [3]byte
			n, err := base64.StdEncoding.Decode(dst[:], t.quad[:])
			if err != nil {
				// Tolerate URL-safe alphabets.
				n, err = base64.URLEncoding.Decode(dst[:], t.quad[:])
				if err != nil {
					t.err = fmt.Errorf("grpc-web-text: %w", err)
					continue
				}
			}
			t.out = append(t.out, dst[:n]...)
		}
	}
	n := copy(p, t.out)
	t.out = t.out[n:]
	return n, nil
}

// EncodeText base64-encodes a binary body for grpc-web-text.
func EncodeText(data []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(out, data)
	return out
}
