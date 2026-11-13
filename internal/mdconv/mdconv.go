// Package mdconv is the fetch_web pipeline: it decodes a fetched document
// to UTF-8, branches on content type (HTML, JSON, text/XML, binary),
// optionally extracts the main article (go-readability) or a CSS selection,
// strips page chrome (scripts, styles, navigation, cookie banners), resolves
// relative URLs and converts the result to GitHub-flavoured Markdown.
package mdconv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	readability "codeberg.org/readeck/go-readability/v2"
	htmltomd "github.com/JohannesKaufmann/html-to-markdown/v2/converter"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/base"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/commonmark"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/strikethrough"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/table"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// Content kinds.
const (
	KindHTML   = "html"
	KindJSON   = "json"
	KindText   = "text"
	KindXML    = "xml"
	KindBinary = "binary"
)

// Options control the HTML pipeline.
type Options struct {
	MainContentOnly bool
	CSSSelector     string
	IncludeLinks    bool
	IncludeImages   bool
	IncludeMetadata bool
}

// Metadata is extracted page metadata.
type Metadata struct {
	Title       string `json:"title,omitempty"`
	Byline      string `json:"byline,omitempty"`
	SiteName    string `json:"site_name,omitempty"`
	Published   string `json:"published,omitempty"`
	Description string `json:"description,omitempty"`
	Language    string `json:"language,omitempty"`
	URL         string `json:"url,omitempty"`
}

// Result is a converted document.
type Result struct {
	Kind     string
	MIMEType string
	Charset  string
	Title    string
	Markdown string
	Metadata Metadata
	Warnings []string
}

// Classify returns the content kind and media type for a body.
func Classify(body []byte, contentType string) (kind, mediaType string) {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil || mt == "" || mt == "application/octet-stream" || mt == "binary/octet-stream" {
		sniff := http.DetectContentType(body)
		mt, _, _ = mime.ParseMediaType(sniff)
		if strings.HasPrefix(mt, "text/plain") {
			trimmed := bytes.TrimSpace(body)
			if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
				mt = "application/json"
			}
		}
	}
	mt = strings.ToLower(mt)
	switch {
	case mt == "text/html" || mt == "application/xhtml+xml":
		return KindHTML, mt
	case mt == "application/json" || mt == "text/json" || strings.HasSuffix(mt, "+json"):
		return KindJSON, mt
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return KindXML, mt
	case strings.HasPrefix(mt, "text/") || mt == "application/javascript" || mt == "application/x-yaml" ||
		mt == "application/yaml" || mt == "application/toml" || mt == "application/x-ndjson":
		return KindText, mt
	}
	return KindBinary, mt
}

// Decode converts body to UTF-8 using the BOM, the Content-Type charset, a
// <meta> prescan (for HTML) or a UTF-8 validity check, falling back to
// windows-1252 as browsers do.
func Decode(body []byte, contentType string) (string, string) {
	e, name, _ := charset.DetermineEncoding(body, contentType)
	if name == "utf-8" {
		b := bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
		if utf8.Valid(b) {
			return string(b), name
		}
		return strings.ToValidUTF8(string(b), "�"), name
	}
	out, err := e.NewDecoder().Bytes(body)
	if err != nil {
		return strings.ToValidUTF8(string(body), "�"), "utf-8"
	}
	return string(out), name
}

// Convert runs the pipeline. pageURL is the final URL (after redirects),
// used to resolve relative links.
func Convert(body []byte, contentType string, pageURL *url.URL, o Options) (*Result, error) {
	kind, mt := Classify(body, contentType)
	res := &Result{Kind: kind, MIMEType: mt}
	if pageURL != nil {
		res.Metadata.URL = pageURL.String()
	}
	switch kind {
	case KindBinary:
		res.Markdown = fmt.Sprintf("_Binary content (%s, %d bytes) is not converted to Markdown. Use http_request with save_to to download it._", orUnknown(mt), len(body))
		return res, nil
	case KindJSON:
		text, cs := Decode(body, "text/plain; charset=utf-8")
		res.Charset = cs
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(strings.TrimSpace(text)), "", "  "); err != nil {
			res.Warnings = append(res.Warnings, "response declared JSON but did not parse: "+err.Error())
			res.Markdown = "```\n" + strings.TrimRight(text, "\n") + "\n```"
		} else {
			res.Markdown = "```json\n" + buf.String() + "\n```"
		}
		return res, nil
	case KindText, KindXML:
		text, cs := Decode(body, contentType)
		res.Charset = cs
		res.Markdown = text
		if kind == KindXML {
			res.Title = xmlTitle(text)
		}
		return res, nil
	}

	text, cs := Decode(body, contentType)
	res.Charset = cs
	md, err := convertHTML(text, pageURL, o, res)
	if err != nil {
		return nil, err
	}
	if o.IncludeMetadata {
		md = frontMatter(res.Metadata) + md
	}
	res.Markdown = md
	return res, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown type"
	}
	return s
}

var xmlTitleRe = regexp.MustCompile(`(?s)<title[^>]*>(.*?)</title>`)

func xmlTitle(s string) string {
	if m := xmlTitleRe.FindStringSubmatch(s); m != nil {
		t := strings.TrimSpace(m[1])
		t = strings.TrimSuffix(strings.TrimPrefix(t, "<![CDATA["), "]]>")
		return strings.TrimSpace(t)
	}
	return ""
}

// Elements removed from every page before extraction.
const junkSelector = "script, style, noscript, template, iframe, object, embed, canvas, svg, dialog, " +
	"form, button, input, select, textarea, link, meta, [hidden], [aria-hidden=true], [style*='display:none'], [style*='display: none']"

// Well-known consent-management platform containers.
const cookieSelector = "#onetrust-consent-sdk, #onetrust-banner-sdk, #CybotCookiebotDialog, #cookiebanner, .cc-window, " +
	".cc-banner, #cookie-law-info-bar, .cookie-law-info-bar, #usercentrics-root, .qc-cmp2-container, #didomi-host, " +
	".fc-consent-root, #truste-consent-track, .truste_box_overlay, [id^=sp_message_container], .osano-cm-window, " +
	"#cmpbox, .cmpboxBG, #iubenda-cs-banner, .termly-styles-root, [aria-label*=cookie i], [aria-label*=consent i]"

// Chrome removed unless the caller targets it with css_selector.
const chromeSelector = "nav, [role=navigation], [role=search]"

var cookieWord = regexp.MustCompile(`(?i)(cookie|consent|gdpr)`)
var bannerWord = regexp.MustCompile(`(?i)(banner|notice|bar|popup|pop-up|modal|dialog|overlay|wall|consent|notification|prompt)`)

func isCookieBanner(s *goquery.Selection) bool {
	for _, attr := range []string{"id", "class"} {
		v, _ := s.Attr(attr)
		for _, tok := range strings.Fields(v) {
			if loc := cookieWord.FindStringIndex(tok); loc != nil {
				rest := tok[:loc[0]] + tok[loc[1]:]
				if bannerWord.MatchString(rest) {
					return true
				}
			}
		}
	}
	return false
}

func clean(doc *goquery.Selection, stripChrome bool) {
	doc.Find(junkSelector).Remove()
	doc.Find(cookieSelector).Remove()
	doc.Find("div, section, aside, footer, header, p").Each(func(_ int, s *goquery.Selection) {
		if isCookieBanner(s) {
			s.Remove()
		}
	})
	if stripChrome {
		doc.Find(chromeSelector).Remove()
	}
}

func convertHTML(text string, pageURL *url.URL, o Options, res *Result) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(text))
	if err != nil {
		return "", fmt.Errorf("parsing HTML: %w", err)
	}
	baseURL := pageURL
	if href, ok := doc.Find("base[href]").First().Attr("href"); ok && baseURL != nil {
		if u, err := baseURL.Parse(strings.TrimSpace(href)); err == nil {
			baseURL = u
		}
	}
	res.Metadata = mergeMeta(res.Metadata, pageMetadata(doc))
	normaliseCodeLanguages(doc.Selection)

	var content *html.Node
	switch {
	case o.CSSSelector != "":
		clean(doc.Selection, false)
		sel := doc.Find(o.CSSSelector)
		if sel.Length() == 0 {
			return "", fmt.Errorf("css_selector %q matched no elements", o.CSSSelector)
		}
		root := &html.Node{Type: html.ElementNode, Data: "div"}
		sel.Each(func(_ int, s *goquery.Selection) {
			for _, n := range s.Nodes {
				if n.Parent != nil {
					n.Parent.RemoveChild(n)
				}
				root.AppendChild(n)
			}
		})
		content = root
	case o.MainContentOnly:
		clean(doc.Selection, true)
		p := readability.NewParser()
		p.KeepClasses = true
		u := baseURL
		if u == nil {
			u = &url.URL{}
		}
		art, err := p.ParseDocument(doc.Nodes[0], u)
		if err == nil && art.Node != nil && strings.TrimSpace(nodeText(art.Node)) != "" {
			content = art.Node
			metaByline := res.Metadata.Byline
			res.Metadata = mergeMeta(Metadata{
				Title:    strings.TrimSpace(art.Title()),
				Byline:   strings.TrimSpace(art.Byline()),
				SiteName: strings.TrimSpace(art.SiteName()),
				Language: art.Language(),
			}, res.Metadata)
			if metaByline != "" {
				// An explicit author meta tag beats the "By ..." heuristic.
				res.Metadata.Byline = metaByline
			}
			if t, err := art.PublishedTime(); err == nil && res.Metadata.Published == "" {
				res.Metadata.Published = t.UTC().Format(time.RFC3339)
			}
		} else {
			res.Warnings = append(res.Warnings, "main content extraction found no article; converted the whole page")
			content = bodyOf(doc)
		}
	default:
		clean(doc.Selection, true)
		content = bodyOf(doc)
	}
	res.Title = res.Metadata.Title

	cs := goquery.NewDocumentFromNode(content).Selection
	postProcess(cs, baseURL, o)

	conv := htmltomd.NewConverter(htmltomd.WithPlugins(
		base.NewBasePlugin(),
		commonmark.NewCommonmarkPlugin(),
		table.NewTablePlugin(),
		strikethrough.NewStrikethroughPlugin(),
	))
	md, err := conv.ConvertNode(content)
	if err != nil {
		return "", fmt.Errorf("converting to Markdown: %w", err)
	}
	return tidy(string(md)), nil
}

func bodyOf(doc *goquery.Document) *html.Node {
	if b := doc.Find("body"); b.Length() > 0 {
		return b.Nodes[0]
	}
	return doc.Nodes[0]
}

func nodeText(n *html.Node) string {
	var sb strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return sb.String()
}

func metaContent(doc *goquery.Document, sels ...string) string {
	for _, s := range sels {
		if v, ok := doc.Find(s).First().Attr("content"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func pageMetadata(doc *goquery.Document) Metadata {
	m := Metadata{
		Title:       metaContent(doc, `meta[property="og:title"]`, `meta[name="twitter:title"]`),
		Byline:      metaContent(doc, `meta[name="author"]`, `meta[property="article:author"]`),
		SiteName:    metaContent(doc, `meta[property="og:site_name"]`, `meta[name="application-name"]`),
		Published:   metaContent(doc, `meta[property="article:published_time"]`, `meta[name="date"]`, `meta[itemprop="datePublished"]`, `meta[name="dc.date"]`, `meta[name="DC.date.issued"]`),
		Description: metaContent(doc, `meta[name="description"]`, `meta[property="og:description"]`),
	}
	if t := strings.TrimSpace(doc.Find("head title").First().Text()); t != "" {
		m.Title = t
	} else if m.Title == "" {
		m.Title = strings.TrimSpace(doc.Find("title").First().Text())
	}
	if m.Published == "" {
		if v, ok := doc.Find("time[datetime]").First().Attr("datetime"); ok {
			m.Published = strings.TrimSpace(v)
		}
	}
	if lang, ok := doc.Find("html").Attr("lang"); ok {
		m.Language = lang
	}
	return m
}

// mergeMeta fills empty fields of a from b.
func mergeMeta(a, b Metadata) Metadata {
	fill := func(x *string, y string) {
		if *x == "" {
			*x = y
		}
	}
	fill(&a.Title, b.Title)
	fill(&a.Byline, b.Byline)
	fill(&a.SiteName, b.SiteName)
	fill(&a.Published, b.Published)
	fill(&a.Description, b.Description)
	fill(&a.Language, b.Language)
	fill(&a.URL, b.URL)
	return a
}

var langClassRe = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|\s)(?:language|lang)-([\w#+.-]+)`),
	regexp.MustCompile(`(?:^|\s)highlight-source-([\w#+.-]+)`),
	regexp.MustCompile(`(?:^|\s)highlight-([\w#+.-]+)`),
	regexp.MustCompile(`brush:\s*([\w#+.-]+)`),
	regexp.MustCompile(`(?:^|\s)sourceCode\s+([\w#+.-]+)`),
}

func langFrom(s *goquery.Selection) string {
	for _, a := range []string{"data-lang", "data-language", "lang"} {
		if v, ok := s.Attr(a); ok && v != "" && !strings.EqualFold(a, "lang") {
			return v
		}
	}
	class, _ := s.Attr("class")
	for _, re := range langClassRe {
		if m := re.FindStringSubmatch(class); m != nil {
			l := strings.ToLower(m[1])
			if l != "text" && l != "plain" && l != "none" && l != "source" {
				return l
			}
		}
	}
	return ""
}

// normaliseCodeLanguages rewrites the many syntax-highlighter conventions
// into class="language-x" on the <code> (or <pre>) element so the Markdown
// fence gets a language hint, and reduces highlighted markup to text.
func normaliseCodeLanguages(doc *goquery.Selection) {
	doc.Find("pre").Each(func(_ int, pre *goquery.Selection) {
		code := pre.ChildrenFiltered("code").First()
		lang := ""
		if code.Length() > 0 {
			lang = langFrom(code)
		}
		if lang == "" {
			lang = langFrom(pre)
		}
		for p, depth := pre.Parent(), 0; lang == "" && p.Length() > 0 && depth < 3; p, depth = p.Parent(), depth+1 {
			lang = langFrom(p)
		}
		if lang == "" {
			return
		}
		if code.Length() > 0 {
			code.SetAttr("class", "language-"+lang)
		} else {
			pre.SetAttr("class", "language-"+lang)
		}
	})
}

func postProcess(s *goquery.Selection, base *url.URL, o Options) {
	resolve := func(v string) string {
		v = strings.TrimSpace(v)
		if base == nil || v == "" {
			return v
		}
		if u, err := base.Parse(v); err == nil {
			return u.String()
		}
		return v
	}
	// Lazy-loaded images.
	s.Find("img").Each(func(_ int, img *goquery.Selection) {
		src, _ := img.Attr("src")
		if src == "" || strings.HasPrefix(src, "data:") {
			for _, a := range []string{"data-src", "data-original", "data-lazy-src"} {
				if v, ok := img.Attr(a); ok && v != "" {
					img.SetAttr("src", v)
					break
				}
			}
		}
		img.RemoveAttr("srcset")
	})
	if o.IncludeImages {
		s.Find("img").Each(func(_ int, img *goquery.Selection) {
			src, _ := img.Attr("src")
			if src == "" || strings.HasPrefix(src, "data:") {
				alt, _ := img.Attr("alt")
				img.ReplaceWithHtml(html.EscapeString(alt))
				return
			}
			img.SetAttr("src", resolve(src))
		})
	} else {
		s.Find("img, picture, video, audio, source, track").Remove()
	}
	s.Find("a").Each(func(_ int, a *goquery.Selection) {
		href, ok := a.Attr("href")
		low := strings.ToLower(strings.TrimSpace(href))
		if !o.IncludeLinks || !ok || strings.HasPrefix(low, "javascript:") {
			a.ReplaceWithSelection(a.Contents())
			return
		}
		a.SetAttr("href", resolve(href))
	})
	// The base plugin removes <head>; drop leftover <title> in fragments.
	s.Find("title").Remove()
}

var manyBlankLines = regexp.MustCompile(`\n{3,}`)

func tidy(md string) string {
	md = strings.ReplaceAll(md, "\r\n", "\n")
	lines := strings.Split(md, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	md = strings.Join(lines, "\n")
	md = manyBlankLines.ReplaceAllString(md, "\n\n")
	return strings.TrimSpace(md) + "\n"
}

func frontMatter(m Metadata) string {
	var b strings.Builder
	b.WriteString("---\n")
	line := func(k, v string) {
		if v == "" {
			return
		}
		q, _ := json.Marshal(v)
		b.WriteString(k + ": " + string(q) + "\n")
	}
	line("title", m.Title)
	line("byline", m.Byline)
	line("site", m.SiteName)
	line("published", m.Published)
	line("url", m.URL)
	b.WriteString("---\n\n")
	return b.String()
}

// Slice returns the window [start, start+max) of md counted in characters
// (runes). next is the start index of the following window, or nil when
// the end was reached. When the content continues, a hint is appended.
func Slice(md string, start, max int) (out string, next *int, total int, err error) {
	runes := []rune(md)
	total = len(runes)
	if start < 0 {
		start = 0
	}
	if start > total || (start == total && total > 0) {
		return "", nil, total, fmt.Errorf("start_index %d is beyond the end of the content (%d characters)", start, total)
	}
	end := total
	if max > 0 && start+max < total {
		end = start + max
	}
	out = string(runes[start:end])
	if end < total {
		n := end
		next = &n
		out += fmt.Sprintf("\n\n[Content truncated: showing characters %d-%d of %d. Call fetch_web again with start_index=%d to continue.]", start, end, total, end)
	}
	return out, next, total, nil
}
