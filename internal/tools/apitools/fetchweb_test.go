package apitools_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
)

type fetchOut struct {
	Status      int    `json:"status"`
	FinalURL    string `json:"final_url"`
	Title       string `json:"title"`
	ContentType string `json:"content_type"`
	Kind        string `json:"kind"`
	Charset     string `json:"charset"`
	SizeBytes   int64  `json:"size_bytes"`
	Metadata    *struct {
		Title    string `json:"title"`
		Byline   string `json:"byline"`
		SiteName string `json:"site_name"`
		URL      string `json:"url"`
	} `json:"metadata"`
	TotalLength    int      `json:"total_length"`
	StartIndex     int      `json:"start_index"`
	NextStartIndex *int     `json:"next_start_index"`
	Markdown       string   `json:"markdown"`
	Warnings       []string `json:"warnings"`
}

// pages serves fixed documents by path.
func pages(t *testing.T, docs map[string]struct {
	ct   string
	body []byte
}) string {
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/article", http.StatusFound)
			return
		}
		if r.URL.Path == "/ua" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("UA=" + r.Header.Get("User-Agent") + " Accept=" + r.Header.Get("Accept")))
			return
		}
		d, ok := docs[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			w.Write([]byte("<html><body><h1>Not found</h1><p>Nothing here.</p></body></html>"))
			return
		}
		if d.ct != "" {
			w.Header().Set("Content-Type", d.ct)
		} else {
			w.Header()["Content-Type"] = nil // suppress sniffing by net/http
		}
		w.Write(d.body)
	})
	return srv.URL
}

type doc = struct {
	ct   string
	body []byte
}

func TestFetchWebArticle(t *testing.T) {
	h := newHarness(t)
	url := pages(t, map[string]doc{"/article": {"text/html; charset=utf-8", testdata(t, "mdconv/testdata/article.html")}})

	r := decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/redirect"}))
	if r.Status != 200 || r.Kind != "html" || r.Charset != "utf-8" || r.FinalURL != url+"/article" {
		t.Fatalf("%+v", r)
	}
	if r.Title == "" || r.Metadata == nil || r.Metadata.Byline != "Ada Lovelace" {
		t.Fatalf("title %q metadata %+v", r.Title, r.Metadata)
	}
	mustContain(t, r.Markdown, "---\ntitle:", "The Go runtime ships with a concurrent", "```bash\nGOGC=200", "## Setting a memory limit", "gc-guide)")
	mustNotContain(t, r.Markdown, "We use cookies", "Accept all", "Tutorials")
	if r.NextStartIndex != nil || r.TotalLength != len([]rune(r.Markdown)) {
		t.Fatalf("paging %v %d", r.NextStartIndex, r.TotalLength)
	}

	// Full page without metadata or links.
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/article",
		"main_content_only": false, "include_metadata": false, "include_links": false}))
	mustNotContain(t, r.Markdown, "---\ntitle:", "](")
	mustContain(t, r.Markdown, "The Go runtime ships")
	if r.Metadata != nil {
		t.Fatalf("metadata %+v", r.Metadata)
	}

	// css_selector overrides main_content_only.
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/article",
		"css_selector": "article .post-body p, article h1", "include_metadata": false}))
	want := strings.ReplaceAll(string(testdata(t, "mdconv/testdata/article.selector.md")), "\r\n", "\n")
	// Links resolve against the test server instead of gazette.example.
	want = strings.ReplaceAll(want, "https://gazette.example/", url+"/")
	if strings.TrimSpace(r.Markdown) != strings.TrimSpace(want) {
		t.Fatalf("selector markdown:\n%s\nwant:\n%s", r.Markdown, want)
	}
	mustNotContain(t, r.Markdown, "```bash")

	h.MustFail("fetch_web", map[string]any{"url": url + "/article", "css_selector": "div.does-not-exist"}, "matched no elements")

	// Error pages are converted with a warning.
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/missing", "main_content_only": false}))
	if r.Status != 404 || len(r.Warnings) == 0 {
		t.Fatalf("%+v", r)
	}
	mustContain(t, r.Markdown, "Not found")
}

func TestFetchWebPaging(t *testing.T) {
	h := newHarness(t)
	var sb strings.Builder
	for i := 0; sb.Len() < 2500; i++ {
		sb.WriteString("línea número ")
		sb.WriteString(strings.Repeat("é", i%7))
		sb.WriteString(" ✓\n")
	}
	text := sb.String()
	url := pages(t, map[string]doc{"/t.txt": {"text/plain; charset=utf-8", []byte(text)}})
	total := len([]rune(text))

	hint := regexp.MustCompile(`\n\n\[Content truncated: [^\]]*\]$`)
	var got strings.Builder
	start, calls := 0, 0
	for {
		args := map[string]any{"url": url + "/t.txt", "max_length": 1000}
		if start > 0 {
			args["start_index"] = start
		}
		r := decode[fetchOut](t, h.MustOK("fetch_web", args))
		calls++
		if r.Kind != "text" || r.TotalLength != total || r.StartIndex != start {
			t.Fatalf("%+v", r)
		}
		if r.NextStartIndex == nil {
			got.WriteString(r.Markdown)
			break
		}
		if *r.NextStartIndex != start+1000 {
			t.Fatalf("next %d after %d", *r.NextStartIndex, start)
		}
		mustContain(t, r.Markdown, "start_index=")
		got.WriteString(hint.ReplaceAllString(r.Markdown, ""))
		start = *r.NextStartIndex
	}
	if got.String() != text {
		t.Fatalf("reassembled text differs (%d vs %d runes)", len([]rune(got.String())), total)
	}
	if want := (total + 999) / 1000; calls != want {
		t.Fatalf("calls %d want %d", calls, want)
	}
	h.MustFail("fetch_web", map[string]any{"url": url + "/t.txt", "start_index": total + 5}, "beyond the end")
	h.MustFail("fetch_web", map[string]any{"url": url + "/t.txt", "start_index": -1}, "")
}

func TestFetchWebContentKinds(t *testing.T) {
	h := newHarness(t)
	png := append([]byte("\x89PNG\r\n\x1a\n"), pattern(500)...)
	latin1 := testdata(t, "mdconv/testdata/latin1.html")
	url := pages(t, map[string]doc{
		"/data.json":  {"application/json", []byte(`{"name":"widget","tags":["a","b"],"n":1}`)},
		"/sniff":      {"", []byte(`[{"x":1}]`)},
		"/img.png":    {"image/png", png},
		"/blob":       {"application/octet-stream", pattern(300)},
		"/latin1":     {"text/html", latin1},
		"/latin1-hdr": {"text/html; charset=ISO-8859-1", latin1},
		"/feed.xml":   {"application/rss+xml", []byte(`<?xml version="1.0"?><rss><channel><title>My Feed</title></channel></rss>`)},
		"/bad.json":   {"application/json", []byte(`{"broken": `)},
	})

	r := decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/data.json"}))
	if r.Kind != "json" || r.Markdown != "```json\n{\n  \"name\": \"widget\",\n  \"tags\": [\n    \"a\",\n    \"b\"\n  ],\n  \"n\": 1\n}\n```" {
		t.Fatalf("%+v", r)
	}
	if r.Metadata != nil {
		t.Fatalf("metadata for json: %+v", r.Metadata)
	}
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/sniff"}))
	if r.Kind != "json" {
		t.Fatalf("sniffed %+v", r)
	}
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/bad.json"}))
	if r.Kind != "json" || len(r.Warnings) == 0 {
		t.Fatalf("%+v", r)
	}

	for _, p := range []string{"/img.png", "/blob"} {
		r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + p}))
		if r.Kind != "binary" {
			t.Fatalf("%s: %+v", p, r)
		}
		mustContain(t, r.Markdown, "Binary content", "save_to")
		mustNotContain(t, r.Markdown, "PNG\r")
	}
	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/img.png"}))
	mustContain(t, r.Markdown, "image/png", "508 bytes")

	wantLatin := strings.ReplaceAll(string(testdata(t, "mdconv/testdata/latin1.md")), "\r\n", "\n")
	for _, p := range []string{"/latin1", "/latin1-hdr"} {
		r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + p, "main_content_only": false, "include_metadata": false}))
		if r.Kind != "html" || r.Charset != "windows-1252" {
			t.Fatalf("%s: kind %s charset %s", p, r.Kind, r.Charset)
		}
		if strings.TrimSpace(r.Markdown) != strings.TrimSpace(wantLatin) {
			t.Fatalf("%s markdown:\n%s\nwant:\n%s", p, r.Markdown, wantLatin)
		}
		if r.Title != "Café menú" {
			t.Fatalf("%s title %q", p, r.Title)
		}
	}

	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/feed.xml"}))
	if r.Kind != "xml" || r.Title != "My Feed" || !strings.HasPrefix(r.Markdown, "<?xml") {
		t.Fatalf("%+v", r)
	}

	r = decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/ua", "user_agent": "TestBot/1.0"}))
	mustContain(t, r.Markdown, "UA=TestBot/1.0", "Accept=text/html")
}

func TestFetchWebTruncatedPage(t *testing.T) {
	h := newHarness(t)
	big := "<html><body><p>" + strings.Repeat("word ", 50000) + "</p></body></html>"
	url := pages(t, map[string]doc{"/big": {"text/html", []byte(big)}})
	r := decode[fetchOut](t, h.MustOK("fetch_web", map[string]any{"url": url + "/big", "max_response_bytes": 4096, "main_content_only": false}))
	if r.Kind != "html" || len(r.Warnings) == 0 || r.SizeBytes != int64(len(big)) {
		t.Fatalf("%+v", r.Warnings)
	}
	mustContain(t, strings.Join(r.Warnings, "\n"), "max_response_bytes")
}

// smallCeiling lowers the server's inline response ceiling to 64 KiB.
func smallCeiling(c *config.Config) {
	c.DefaultResponseBytes = 16 << 10
	c.MaxResponseBytes = 64 << 10
}

// A per-call max_response_bytes above the server ceiling must be clamped.
func TestResponseCeilingClamped(t *testing.T) {
	h := newHarness(t, smallCeiling)
	text := strings.Repeat("abcdefghij", 20<<10) // 200 KiB
	url := pages(t, map[string]doc{"/big.txt": {"text/plain", []byte(text)}})
	for _, max := range []any{nil, 10 << 20} {
		args := map[string]any{"url": url + "/big.txt", "max_length": 1}
		if max != nil {
			args["max_response_bytes"] = max
		}
		r := decode[fetchOut](t, h.MustOK("fetch_web", args))
		if r.TotalLength != 64<<10 || r.SizeBytes != int64(len(text)) {
			t.Fatalf("max %v: total_length %d size %d", max, r.TotalLength, r.SizeBytes)
		}
		mustContain(t, strings.Join(r.Warnings, "\n"), "65536 bytes")
	}

	intro := append(testdata(t, "graphqlx/testdata/introspection.json"), []byte(strings.Repeat(" ", 100<<10))...)
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(intro)
	})
	h.MustFail("graphql_introspect", map[string]any{"url": srv.URL, "max_response_bytes": 10 << 20}, "truncated at 65536 bytes")
}
