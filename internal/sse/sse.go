// Package sse implements a spec-compliant Server-Sent Events parser
// (WHATWG HTML "event stream interpretation").
//
// It handles a leading UTF-8 BOM, CRLF / LF / CR line endings, multi-line
// data, comments, the event, id and retry fields, and the rule that an
// incomplete event at end of stream is discarded.
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Event is one dispatched event.
type Event struct {
	// Event is the event type ("message" when the stream did not name one).
	Event string
	// ID is the last event ID in effect when the event was dispatched.
	ID string
	// Data is the event data; multiple data lines are joined with "\n".
	Data string
	// Retry is the reconnection time in milliseconds, or -1 when the event
	// did not carry a retry field.
	Retry int
}

var bom = string(rune(0xFEFF))

// DefaultMaxLine bounds a single line (16 MiB).
const DefaultMaxLine = 16 << 20

// ErrLineTooLong is returned when a line exceeds the reader's limit.
var ErrLineTooLong = errors.New("sse: line too long")

// Reader parses events from a stream.
type Reader struct {
	sc       *bufio.Scanner
	started  bool
	lastID   string
	data     strings.Builder
	hasData  bool
	event    string
	retry    int
	comments int
	// OnComment, when set, is called for every comment line (without the
	// leading colon).
	OnComment func(string)
}

// NewReader returns a parser over r. maxLine bounds the length of a single
// line (0 = DefaultMaxLine).
func NewReader(r io.Reader, maxLine int) *Reader {
	if maxLine <= 0 {
		maxLine = DefaultMaxLine
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(4096, maxLine)), maxLine)
	sc.Split(scanLines)
	return &Reader{sc: sc, retry: -1}
}

// LastEventID returns the last event ID seen.
func (r *Reader) LastEventID() string { return r.lastID }

// Comments returns the number of comment lines seen.
func (r *Reader) Comments() int { return r.comments }

// Next returns the next dispatched event. It returns io.EOF at the end of the
// stream (an incomplete trailing event is discarded, as the spec requires).
func (r *Reader) Next() (Event, error) {
	for r.sc.Scan() {
		line := r.sc.Text()
		if !r.started {
			r.started = true
			line = strings.TrimPrefix(line, bom)
		}
		if line == "" {
			if ev, ok := r.dispatch(); ok {
				return ev, nil
			}
			continue
		}
		if line[0] == ':' {
			r.comments++
			if r.OnComment != nil {
				r.OnComment(strings.TrimPrefix(line[1:], " "))
			}
			continue
		}
		field, value := line, ""
		if i := strings.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			value = strings.TrimPrefix(value, " ")
		}
		r.process(field, value)
	}
	if err := r.sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return Event{}, ErrLineTooLong
		}
		return Event{}, err
	}
	return Event{}, io.EOF
}

func (r *Reader) process(field, value string) {
	switch field {
	case "event":
		r.event = value
	case "data":
		if r.hasData {
			r.data.WriteByte('\n')
		}
		r.data.WriteString(value)
		r.hasData = true
	case "id":
		if !strings.ContainsRune(value, 0) {
			r.lastID = value
		}
	case "retry":
		if value != "" && strings.Trim(value, "0123456789") == "" {
			if n, err := strconv.Atoi(value); err == nil {
				r.retry = n
			}
		}
	}
	// Unknown fields are ignored.
}

func (r *Reader) dispatch() (Event, bool) {
	retry := r.retry
	r.retry = -1
	if !r.hasData {
		// Spec: if the data buffer is empty, reset and do not dispatch.
		r.event = ""
		r.data.Reset()
		return Event{}, false
	}
	ev := Event{Event: r.event, ID: r.lastID, Data: r.data.String(), Retry: retry}
	if ev.Event == "" {
		ev.Event = "message"
	}
	r.event = ""
	r.data.Reset()
	r.hasData = false
	return ev, true
}

// scanLines splits on CRLF, LF or a lone CR.
func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		if data[i] == '\n' {
			return i + 1, data[:i], nil
		}
		// CR: need one more byte to know whether it is CRLF.
		if i+1 < len(data) {
			if data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
			return i + 1, data[:i], nil
		}
		if atEOF {
			return i + 1, data[:i], nil
		}
		return 0, nil, nil
	}
	if atEOF {
		// A final line without terminator is not a complete line; the spec
		// discards it together with any pending event, which Next does by
		// never dispatching it. Return it so field parsing stays uniform.
		return len(data), data, nil
	}
	return 0, nil, nil
}
