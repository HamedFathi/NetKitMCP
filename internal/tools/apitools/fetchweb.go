package apitools

import (
	"context"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/mdconv"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const (
	defaultFetchMaxLength = 20000
	// fetchReadBytes is the default page read limit; real pages often exceed
	// the 1 MiB inline default of other tools.
	fetchReadBytes = 10 << 20
)

type fetchIn struct {
	URL             string            `json:"url" jsonschema:"page URL (http or https)"`
	UserAgent       string            `json:"user_agent,omitempty" jsonschema:"User-Agent header (default: the server's user agent)"`
	Headers         map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	MainContentOnly *bool             `json:"main_content_only,omitempty" jsonschema:"extract the main article with readability (default true)"`
	CSSSelector     string            `json:"css_selector,omitempty" jsonschema:"convert only elements matching this CSS selector (overrides main_content_only)"`
	IncludeLinks    *bool             `json:"include_links,omitempty" jsonschema:"keep hyperlinks as Markdown links (default true)"`
	IncludeImages   bool              `json:"include_images,omitempty" jsonschema:"keep images as Markdown images (default false)"`
	IncludeMetadata *bool             `json:"include_metadata,omitempty" jsonschema:"prepend title, byline, site and published date as front matter (default true)"`
	MaxLength       int               `json:"max_length,omitempty" jsonschema:"maximum Markdown characters returned (default 20000)"`
	StartIndex      int               `json:"start_index,omitempty" jsonschema:"character offset to continue from (use next_start_index of the previous call)"`
	Auth            *auth.Config      `json:"auth,omitempty"`
	types.HTTPOptions
}

type fetchOut struct {
	Status         int              `json:"status"`
	StatusText     string           `json:"status_text"`
	FinalURL       string           `json:"final_url"`
	Title          string           `json:"title,omitempty"`
	ContentType    string           `json:"content_type,omitempty"`
	Kind           string           `json:"kind"`
	Charset        string           `json:"charset,omitempty"`
	SizeBytes      int64            `json:"size_bytes"`
	Metadata       *mdconv.Metadata `json:"metadata,omitempty"`
	TotalLength    int              `json:"total_length"`
	StartIndex     int              `json:"start_index"`
	NextStartIndex *int             `json:"next_start_index"`
	Markdown       string           `json:"markdown"`
	TimingMS       types.Timing     `json:"timing_ms"`
	Warnings       []string         `json:"warnings,omitempty"`
}

func registerFetchWeb(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "fetch_web", "Fetch a web page as Markdown",
		"Fetch a URL and return clean GitHub-flavoured Markdown: decodes the charset, extracts the main article (main_content_only, default true) or a css_selector, "+
			"strips scripts, navigation and cookie banners, resolves relative links. JSON is pretty-printed, text/XML passed through, binary reported as metadata only. "+
			"Long pages are paged: pass next_start_index back as start_index. JavaScript is not executed, so client-rendered pages may come back empty.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in fetchIn) (any, error) {
			return fetchWeb(ctx, d, in)
		})
}

func fetchWeb(ctx context.Context, d *tools.Deps, in fetchIn) (any, error) {
	u, err := checkURL(in.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	if in.MaxLength < 0 || in.StartIndex < 0 {
		return nil, fmt.Errorf("max_length and start_index must not be negative")
	}
	opts := in.HTTPOptions
	if opts.MaxResponseBytes == 0 {
		opts.MaxResponseBytes = fetchReadBytes
	}
	// Clamp to the server ceiling: ReadOptions.MaxBytes is not clamped by
	// httpx, so a raw user value would bypass max_response_bytes limits.
	opts.MaxResponseBytes = d.Cfg.ResponseBytes(opts.MaxResponseBytes)
	defaults := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
		"Accept-Language": "en;q=0.9, *;q=0.5",
	}
	if in.UserAgent != "" {
		defaults["User-Agent"] = in.UserAgent
	}
	resp, err := do(ctx, d, opts, in.Auth, call{Method: "GET", URL: u.String(), Headers: in.Headers, Defaults: defaults,
		Read: httpx.ReadOptions{MaxBytes: opts.MaxResponseBytes}})
	if err != nil {
		return nil, err
	}
	out := fetchOut{Status: resp.Status, StatusText: resp.StatusText, FinalURL: resp.FinalURL, ContentType: resp.ContentType,
		SizeBytes: resp.SizeBytes, TimingMS: resp.TimingMS, StartIndex: in.StartIndex, Warnings: resp.Warnings}
	if resp.Status/100 != 2 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("server answered HTTP %d %s; the converted error page is returned", resp.Status, resp.StatusText))
	}
	pageURL, _ := url.Parse(resp.FinalURL)
	if pageURL == nil {
		pageURL = u
	}
	o := mdconv.Options{
		MainContentOnly: types.BoolDefault(in.MainContentOnly, true) && in.CSSSelector == "",
		CSSSelector:     in.CSSSelector,
		IncludeLinks:    types.BoolDefault(in.IncludeLinks, true),
		IncludeImages:   in.IncludeImages,
		IncludeMetadata: types.BoolDefault(in.IncludeMetadata, true),
	}
	res, err := mdconv.Convert(rawBody(resp), resp.ContentType, pageURL, o)
	if err != nil {
		return nil, fmt.Errorf("converting page: %w", err)
	}
	out.Kind, out.Charset, out.Title = res.Kind, res.Charset, res.Title
	if out.Title == "" {
		out.Title = res.Metadata.Title
	}
	if o.IncludeMetadata && res.Kind == mdconv.KindHTML {
		m := res.Metadata
		out.Metadata = &m
	}
	out.Warnings = append(out.Warnings, res.Warnings...)
	max := in.MaxLength
	if max == 0 {
		max = defaultFetchMaxLength
	}
	md, next, total, err := mdconv.Slice(res.Markdown, in.StartIndex, max)
	if err != nil {
		return nil, err
	}
	out.Markdown, out.NextStartIndex, out.TotalLength = md, next, total
	if resp.Truncated {
		out.Warnings = append(out.Warnings, fmt.Sprintf("page was cut at %d bytes before conversion; raise max_response_bytes for the full page", opts.MaxResponseBytes))
	}
	return out, nil
}
