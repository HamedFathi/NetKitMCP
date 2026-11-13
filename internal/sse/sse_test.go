package sse

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func collect(t *testing.T, r io.Reader) []Event {
	t.Helper()
	p := NewReader(r, 0)
	var out []Event
	for {
		ev, err := p.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
}

func TestParse(t *testing.T) {
	in := bom + ": welcome comment\r\n" +
		"data: first\r\n" +
		"data:  second line keeps one space\r\n" +
		"\r\n" +
		"event: update\n" +
		"id: 42\n" +
		"retry: 1500\n" +
		"data: {\"a\":1}\n" +
		"\n" +
		"id\n" + // empty id resets
		"data\n" + // empty data line
		"\n" +
		"event: ignored-no-data\n" +
		"\n" +
		"data: cr only\r\r" +
		"unknown: field\n" +
		"retry: abc\n" +
		"data: x\n\n" +
		"data: incomplete trailing event"
	got := collect(t, strings.NewReader(in))
	want := []Event{
		{Event: "message", Data: "first\n second line keeps one space", Retry: -1},
		{Event: "update", ID: "42", Data: `{"a":1}`, Retry: 1500},
		{Event: "message", ID: "", Data: "", Retry: -1},
		{Event: "message", ID: "", Data: "cr only", Retry: -1},
		{Event: "message", ID: "", Data: "x", Retry: -1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
}

func TestByteAtATime(t *testing.T) {
	in := "data: a\r\ndata: b\r\n\r\nevent: done\r\ndata: [DONE]\r\n\r\n"
	got := collect(t, iotest.OneByteReader(strings.NewReader(in)))
	if len(got) != 2 || got[0].Data != "a\nb" || got[1].Event != "done" || got[1].Data != "[DONE]" {
		t.Fatalf("got %#v", got)
	}
}

func TestComments(t *testing.T) {
	p := NewReader(strings.NewReader(":ping\n: keepalive\n\ndata: x\n\n"), 0)
	var cs []string
	p.OnComment = func(s string) { cs = append(cs, s) }
	ev, err := p.Next()
	if err != nil || ev.Data != "x" {
		t.Fatal(ev, err)
	}
	if p.Comments() != 2 || !reflect.DeepEqual(cs, []string{"ping", "keepalive"}) {
		t.Fatal(cs)
	}
}

func TestLineTooLong(t *testing.T) {
	p := NewReader(strings.NewReader("data: "+strings.Repeat("x", 100)+"\n\n"), 32)
	if _, err := p.Next(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err = %v", err)
	}
}
