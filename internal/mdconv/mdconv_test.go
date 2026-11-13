package mdconv

import (
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
		t.Fatalf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestGolden(t *testing.T) {
	cases := []struct {
		name, in, ct, url, out string
		opts                   Options
	}{
		{"tables and code, full page", "tables_code.html", "text/html; charset=utf-8", "https://example.com/docs/api/widgets.html", "tables_code.md",
			Options{IncludeLinks: true, IncludeImages: true}},
		{"tables and code, no links or images", "tables_code.html", "text/html", "https://example.com/docs/api/widgets.html", "tables_code.nolinks.md",
			Options{}},
		{"article main content", "article.html", "text/html; charset=utf-8", "https://gazette.example/2026/03/gc", "article.main.md",
			Options{MainContentOnly: true, IncludeLinks: true, IncludeMetadata: true}},
		{"article full page", "article.html", "text/html", "https://gazette.example/2026/03/gc", "article.full.md",
			Options{IncludeLinks: true}},
		{"article css selector", "article.html", "text/html", "https://gazette.example/2026/03/gc", "article.selector.md",
			Options{CSSSelector: "article .post-body p, article h1", IncludeLinks: true}},
		{"legacy charset via meta", "latin1.html", "text/html", "http://old.example/menu", "latin1.md",
			Options{MainContentOnly: false, IncludeLinks: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", c.in))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Convert(body, c.ct, mustURL(c.url), c.opts)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, c.out, res.Markdown)
		})
	}
}

func TestMetadataAndTitle(t *testing.T) {
	body, _ := os.ReadFile("testdata/article.html")
	res, err := Convert(body, "text/html", mustURL("https://gazette.example/a"), Options{MainContentOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	m := res.Metadata
	if res.Title == "" || m.Byline != "Ada Lovelace" || m.SiteName != "The Gopher Gazette" || !strings.HasPrefix(m.Published, "2026-03-14") {
		t.Fatalf("%+v title=%q", m, res.Title)
	}
	for _, junk := range []string{"cookies", "Popular posts", "Accept all", "Tutorials"} {
		if strings.Contains(res.Markdown, junk) {
			t.Fatalf("main content contains %q:\n%s", junk, res.Markdown)
		}
	}
}

func TestLegacyCharset(t *testing.T) {
	body, _ := os.ReadFile("testdata/latin1.html")
	res, err := Convert(body, "text/html", mustURL("http://old.example/"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Charset != "windows-1252" || res.Title != "Café menú" {
		t.Fatalf("charset=%q title=%q", res.Charset, res.Title)
	}
	for _, want := range []string{"“Le Château”", "Crème brûlée costs 5€ – naïve price © 2026."} {
		if !strings.Contains(res.Markdown, want) {
			t.Fatalf("missing %q in:\n%s", want, res.Markdown)
		}
	}
}

func TestSelectorNoMatch(t *testing.T) {
	_, err := Convert([]byte("<p>x</p>"), "text/html", mustURL("http://h/"), Options{CSSSelector: ".nope"})
	if err == nil || !strings.Contains(err.Error(), "matched no elements") {
		t.Fatal(err)
	}
}

func TestNonHTML(t *testing.T) {
	res, err := Convert([]byte(`{"b":[1,2],"a":"x"}`), "application/json", nil, Options{})
	if err != nil || res.Kind != KindJSON || res.Markdown != "```json\n{\n  \"b\": [\n    1,\n    2\n  ],\n  \"a\": \"x\"\n}\n```" {
		t.Fatalf("%q %v", res.Markdown, err)
	}
	// JSON sniffed when content type is missing.
	res, _ = Convert([]byte(`[1]`), "", nil, Options{})
	if res.Kind != KindJSON {
		t.Fatal(res.Kind)
	}
	res, _ = Convert([]byte("plain *text*\n"), "text/plain", nil, Options{})
	if res.Kind != KindText || res.Markdown != "plain *text*\n" {
		t.Fatal(res.Markdown)
	}
	res, _ = Convert([]byte(`<?xml version="1.0"?><rss><channel><title>Feed</title></channel></rss>`), "application/rss+xml", nil, Options{})
	if res.Kind != KindXML || res.Title != "Feed" || !strings.HasPrefix(res.Markdown, "<?xml") {
		t.Fatal(res.Kind, res.Title)
	}
	res, _ = Convert([]byte("%PDF-1.7\n\x00\x01binary"), "application/pdf", nil, Options{})
	if res.Kind != KindBinary || !strings.Contains(res.Markdown, "application/pdf") {
		t.Fatal(res.Markdown)
	}
	res, _ = Convert([]byte{0x89, 'P', 'N', 'G', 0, 0, 0}, "", nil, Options{})
	if res.Kind != KindBinary {
		t.Fatal(res.Kind)
	}
}

func TestSlice(t *testing.T) {
	md := "héllo wörld" // 11 runes
	out, next, total, err := Slice(md, 0, 5)
	if err != nil || total != 11 || next == nil || *next != 5 || !strings.HasPrefix(out, "héllo\n\n[Content truncated") || !strings.Contains(out, "start_index=5") {
		t.Fatalf("%q %v %d %v", out, next, total, err)
	}
	out, next, _, _ = Slice(md, 5, 100)
	if out != " wörld" || next != nil {
		t.Fatalf("%q %v", out, next)
	}
	if _, _, _, err := Slice(md, 11, 5); err == nil {
		t.Fatal("expected error past the end")
	}
	out, next, _, err = Slice("", 0, 10)
	if err != nil || out != "" || next != nil {
		t.Fatal(out, err)
	}
}
