package curlparse

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Tool names produced by Parse.
const (
	ToolRequest   = "http_request"
	ToolForm      = "http_form_request"
	ToolMultipart = "http_multipart_request"
	ToolUpload    = "http_upload"
)

// Result is the converted command: call Tool with Arguments.
type Result struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Warnings  []string       `json:"warnings,omitempty"`
}

// short maps single-letter options to their long names.
var short = map[byte]string{
	'X': "request", 'H': "header", 'd': "data", 'F': "form", 'u': "user", 'A': "user-agent",
	'e': "referer", 'b': "cookie", 'c': "cookie-jar", 'k': "insecure", 'L': "location",
	'm': "max-time", 'x': "proxy", 'U': "proxy-user", 'G': "get", 'I': "head", 'o': "output",
	'O': "remote-name", 'T': "upload-file", 's': "silent", 'S': "show-error", 'v': "verbose",
	'i': "include", 'f': "fail", '#': "progress-bar", 'w': "write-out", 'D': "dump-header",
	'E': "cert", 'K': "config", 'r': "range", 'z': "time-cond", '0': "http1.0", '1': "tlsv1",
	'2': "sslv2", '3': "sslv3", '4': "ipv4", '6': "ipv6", 'g': "globoff", 'N': "no-buffer",
	'n': "netrc", 'j': "junk-session-cookies", 'q': "disable", 'R': "remote-time", 'Y': "speed-limit",
	'y': "speed-time", 'C': "continue-at", 'J': "remote-header-name", 'p': "proxytunnel",
	'Z': "parallel", 'M': "manual", 'V': "version", 'h': "help", 'B': "use-ascii", 'a': "append",
	'l': "list-only", 'P': "ftp-port", 'Q': "quote", 't': "telnet-option",
}

// withArg lists long options that take a value.
var withArg = setOf(
	"request", "header", "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "json",
	"form", "form-string", "user", "user-agent", "referer", "cookie", "cookie-jar", "max-time",
	"proxy", "proxy-user", "output", "upload-file", "write-out", "dump-header", "cert", "key",
	"cacert", "capath", "config", "range", "time-cond", "speed-limit", "speed-time", "continue-at",
	"url", "oauth2-bearer", "aws-sigv4", "max-redirs", "connect-timeout", "retry", "retry-delay",
	"retry-max-time", "limit-rate", "keepalive-time", "interface", "dns-servers", "resolve",
	"connect-to", "output-dir", "trace", "trace-ascii", "stderr", "max-filesize", "ciphers",
	"tls-max", "pinnedpubkey", "cert-type", "key-type", "pass", "proxy-cacert", "proxy-cert",
	"proxy-key", "socks4", "socks4a", "socks5", "socks5-hostname", "preproxy", "noproxy",
	"expect100-timeout", "happy-eyeballs-timeout-ms", "request-target", "unix-socket",
	"abstract-unix-socket", "variable", "ftp-port", "quote", "telnet-option", "mail-from",
	"mail-rcpt", "local-port", "proto", "proto-redir", "proto-default", "hostpubmd5",
	"hostpubsha256", "pubkey", "krb", "delegation", "service-name", "sasl-authzid",
	"login-options", "egd-file", "random-file", "etag-save", "etag-compare", "header-file",
	"proxy-header", "doh-url", "parallel-max", "rate", "create-file-mode", "ip-tos", "vlan-priority",
	"url-query", "write-out", "ech", "curves", "tls13-ciphers", "proxy-ciphers", "alt-svc", "hsts",
	"ssl-sessions",
)

// ignored options have no effect on the request semantics.
var ignored = setOf(
	"silent", "show-error", "verbose", "include", "fail", "fail-with-body", "progress-bar",
	"write-out", "dump-header", "globoff", "no-buffer", "no-progress-meter", "path-as-is",
	"tcp-nodelay", "no-keepalive", "keepalive-time", "trace", "trace-ascii", "stderr",
	"ipv4", "ipv6", "remote-time", "create-dirs", "cookie-jar", "junk-session-cookies",
	"styled-output", "no-styled-output", "tr-encoding", "parallel", "parallel-max",
	"limit-rate", "speed-limit", "speed-time", "retry-delay", "retry-max-time",
	"retry-connrefused", "retry-all-errors", "no-sessionid", "no-alpn", "no-npn",
	"tcp-fastopen", "disable", "fail-early", "show-headers", "remote-header-name",
	"tlsv1", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "sslv2", "sslv3", "suppress-connect-headers",
	"keepalive", "sessionid", "buffer", "progress-meter", "ssl-reqd", "ssl", "ssl-no-revoke",
	"ssl-allow-beast", "ssl-revoke-best-effort", "doh-insecure", "http0.9", "proxy-http2",
)

func setOf(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

type header struct{ name, value string }

type dataItem struct {
	value  string // raw (already form-encoded) text
	file   string // file reference (@file)
	strips bool   // curl strips CR/LF from the file (-d @file)
	encode string // for --data-urlencode name@file: the name
}

type formItem struct {
	name, value           string
	file, filename, ctype string
	fromContent, isFile   bool
	headers               map[string]string
}

type state struct {
	method      string
	urls        []string
	headers     []header
	data        []dataItem
	forms       []formItem
	user        string
	hasUser     bool
	authType    string
	bearer      string
	awsSigV4    string
	get         bool
	head        bool
	insecure    bool
	location    *bool
	maxRedirs   int
	compressed  bool
	maxTime     float64
	connTimeout float64
	proxy       string
	proxyUser   string
	httpVersion string
	output      string
	remoteName  bool
	upload      string
	cacert      string
	cert, key   string
	jsonMode    bool
	retries     int
	warnings    []string
}

func (s *state) warn(format string, args ...any) {
	s.warnings = append(s.warnings, fmt.Sprintf(format, args...))
}

// Parse converts a curl command line into tool arguments.
func Parse(cmd string) (*Result, error) {
	toks, err := Tokenize(cmd)
	if err != nil {
		return nil, err
	}
	// Drop a shell prompt and the program name.
	for len(toks) > 0 && (toks[0] == "$" || toks[0] == ">" || toks[0] == "%") {
		toks = toks[1:]
	}
	if len(toks) > 0 {
		base := strings.ToLower(path.Base(strings.ReplaceAll(toks[0], `\`, "/")))
		if base == "curl" || base == "curl.exe" {
			toks = toks[1:]
		}
	}
	if len(toks) == 0 {
		return nil, errors.New("empty curl command")
	}
	s := &state{}
	if err := s.parseArgs(toks); err != nil {
		return nil, err
	}
	return s.build()
}

func (s *state) parseArgs(toks []string) error {
	endOfOpts := false
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		next := func(name string) (string, error) {
			if i+1 >= len(toks) {
				return "", fmt.Errorf("option %s needs a value", name)
			}
			i++
			return toks[i], nil
		}
		switch {
		case endOfOpts || t == "-" || !strings.HasPrefix(t, "-"):
			s.urls = append(s.urls, t)
		case t == "--":
			endOfOpts = true
		case strings.HasPrefix(t, "--"):
			name := t[2:]
			var val string
			hasVal := false
			if !withArg[name] && !s.isKnownFlag(name) {
				if eq := strings.IndexByte(name, '='); eq > 0 && withArg[name[:eq]] {
					name, val, hasVal = name[:eq], name[eq+1:], true
				}
			}
			if withArg[name] && !hasVal {
				v, err := next("--" + name)
				if err != nil {
					return err
				}
				val = v
			}
			if err := s.apply(name, val); err != nil {
				return err
			}
		default:
			// Short option cluster, e.g. -sSL or -XPOST.
			for j := 1; j < len(t); j++ {
				name, ok := short[t[j]]
				if !ok {
					s.warn("unsupported option -%c ignored", t[j])
					continue
				}
				if withArg[name] {
					val := t[j+1:]
					if val == "" {
						v, err := next("-" + string(t[j]))
						if err != nil {
							return err
						}
						val = v
					}
					if err := s.apply(name, val); err != nil {
						return err
					}
					break
				}
				if err := s.apply(name, ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var knownFlags = setOf(
	"insecure", "location", "location-trusted", "get", "head", "compressed", "remote-name",
	"http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3", "http3-only", "digest",
	"basic", "ntlm", "ntlm-wb", "negotiate", "anyauth", "no-location", "no-insecure",
	"no-compressed", "proxytunnel", "netrc", "netrc-optional", "remote-name-all", "manual",
	"version", "help", "next", "continue-at", "use-ascii", "append", "list-only",
)

func (s *state) isKnownFlag(name string) bool { return knownFlags[name] || ignored[name] }

func (s *state) apply(name, val string) error {
	switch name {
	case "request":
		s.method = val
	case "url":
		s.urls = append(s.urls, val)
	case "header":
		s.addHeaderLine(val)
	case "data", "data-ascii":
		s.addData(val, true, false)
	case "data-binary":
		s.addData(val, true, true)
	case "data-raw":
		s.data = append(s.data, dataItem{value: val})
	case "json":
		s.jsonMode = true
		s.addData(val, true, true)
	case "data-urlencode":
		s.addURLEncoded(val)
	case "form":
		return s.addForm(val, false)
	case "form-string":
		return s.addForm(val, true)
	case "user":
		s.user, s.hasUser = val, true
	case "basic":
		s.authType = "basic"
	case "digest":
		s.authType = "digest"
	case "ntlm", "ntlm-wb":
		s.authType = "ntlm"
	case "negotiate":
		s.authType = "negotiate"
	case "anyauth":
		s.warn("--anyauth: no auth negotiation; using basic unless another type is set")
	case "oauth2-bearer":
		s.bearer = val
	case "aws-sigv4":
		s.awsSigV4 = val
	case "user-agent":
		s.headers = append(s.headers, header{"User-Agent", val})
	case "referer":
		if ref := strings.TrimSuffix(val, ";auto"); ref != "" {
			s.headers = append(s.headers, header{"Referer", ref})
		}
	case "cookie":
		if strings.Contains(val, "=") {
			s.headers = append(s.headers, header{"Cookie", val})
		} else {
			s.warn("-b %s reads cookies from a file; not supported (pass a Cookie header instead)", val)
		}
	case "range":
		s.headers = append(s.headers, header{"Range", "bytes=" + val})
	case "insecure":
		s.insecure = true
	case "no-insecure":
		s.insecure = false
	case "location", "location-trusted":
		t := true
		s.location = &t
		if name == "location-trusted" {
			s.warn("--location-trusted: credentials are handled by Go's redirect policy (Authorization is dropped on cross-host redirects)")
		}
	case "no-location":
		f := false
		s.location = &f
	case "max-redirs":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("--max-redirs: %q is not a number", val)
		}
		s.maxRedirs = n
	case "compressed":
		s.compressed = true
	case "no-compressed":
		s.compressed = false
	case "max-time":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return fmt.Errorf("--max-time: %q is not a number", val)
		}
		s.maxTime = f
	case "connect-timeout":
		f, err := strconv.ParseFloat(val, 64)
		if err == nil {
			s.connTimeout = f
		}
	case "proxy":
		s.proxy = val
	case "socks5", "socks4", "socks4a":
		s.proxy = "socks5://" + val
		if name != "socks5" {
			s.warn("--%s: SOCKS4 is not supported; using SOCKS5", name)
		}
	case "socks5-hostname":
		s.proxy = "socks5h://" + val
	case "proxy-user":
		s.proxyUser = val
	case "get":
		s.get = true
	case "head":
		s.head = true
	case "http1.0", "http1.1":
		s.httpVersion = "1.1"
		if name == "http1.0" {
			s.warn("--http1.0: HTTP/1.0 is not supported; using HTTP/1.1")
		}
	case "http2", "http2-prior-knowledge":
		s.httpVersion = "2"
	case "http3", "http3-only":
		s.httpVersion = "3"
	case "output":
		s.output = val
	case "remote-name", "remote-name-all":
		s.remoteName = true
	case "upload-file":
		s.upload = val
	case "cacert":
		s.cacert = val
	case "cert":
		c := val
		if i := strings.LastIndex(c, ":"); i > 1 && !strings.Contains(c[i:], `\`) && !strings.Contains(c[i:], "/") {
			s.warn("--cert: certificate passphrases are not supported; the key must be unencrypted")
			c = c[:i]
		}
		s.cert = c
	case "key":
		s.key = val
	case "retry":
		n, err := strconv.Atoi(val)
		if err == nil {
			s.retries = n
		}
	case "next":
		s.warn("--next: only the first request is converted")
	case "config":
		s.warn("-K/--config %s: config files are not read", val)
	case "resolve", "connect-to":
		s.warn("--%s %s is not supported (netkit resolves hosts itself)", name, val)
	case "header-file":
		s.warn("--header-file is not supported; pass headers explicitly")
	case "proxy-header":
		s.warn("--proxy-header is not supported")
	case "unix-socket", "abstract-unix-socket":
		s.warn("--%s is not supported", name)
	case "request-target":
		s.warn("--request-target is not supported")
	case "url-query":
		s.warn("--url-query is not supported; add the parameters to the URL or the query argument")
	case "output-dir":
		s.warn("--output-dir is not supported; save_to takes a full path")
	case "max-filesize":
		s.warn("--max-filesize: use max_download_bytes or max_response_bytes")
	case "netrc", "netrc-optional":
		s.warn("--%s: .netrc files are not read; pass auth explicitly", name)
	case "proxytunnel":
		// HTTPS through a proxy is always tunnelled.
	case "time-cond":
		s.warn("-z/--time-cond is not supported; send an If-Modified-Since header instead")
	case "continue-at":
		s.warn("-C/--continue-at is not supported; send a Range header instead")
	default:
		switch {
		case ignored[name]:
		case withArg[name]:
			s.warn("unsupported option --%s ignored", name)
		case strings.HasPrefix(name, "no-") && (ignored[name[3:]] || withArg[name[3:]] || knownFlags[name[3:]]):
		default:
			s.warn("unsupported option --%s ignored", name)
		}
	}
	return nil
}

func (s *state) addHeaderLine(v string) {
	if strings.HasPrefix(v, "@") {
		s.warn("-H %s reads headers from a file; not supported", v)
		return
	}
	if i := strings.IndexByte(v, ':'); i > 0 {
		name := strings.TrimSpace(v[:i])
		val := strings.TrimSpace(v[i+1:])
		if val == "" {
			// "Name:" removes a default header in curl.
			s.headers = append(s.headers, header{name, "\x00remove"})
			return
		}
		s.headers = append(s.headers, header{name, val})
		return
	}
	if strings.HasSuffix(v, ";") {
		s.headers = append(s.headers, header{strings.TrimSpace(strings.TrimSuffix(v, ";")), ""})
		return
	}
	s.warn("ignored malformed header %q", v)
}

func (s *state) addData(v string, allowFile, binary bool) {
	if allowFile && strings.HasPrefix(v, "@") {
		f := v[1:]
		if f == "-" {
			s.warn("reading data from stdin (@-) is not supported")
			return
		}
		s.data = append(s.data, dataItem{file: f, strips: !binary})
		return
	}
	if !binary {
		v = strings.NewReplacer("\r", "", "\n", "").Replace(v)
	}
	s.data = append(s.data, dataItem{value: v})
}

func (s *state) addURLEncoded(v string) {
	switch {
	case strings.HasPrefix(v, "="):
		s.data = append(s.data, dataItem{value: curlEscape(v[1:])})
	case strings.HasPrefix(v, "@"):
		s.data = append(s.data, dataItem{file: v[1:], encode: "\x00"})
	default:
		eq := strings.IndexByte(v, '=')
		at := strings.IndexByte(v, '@')
		switch {
		case eq > 0 && (at < 0 || eq < at):
			s.data = append(s.data, dataItem{value: v[:eq] + "=" + curlEscape(v[eq+1:])})
		case at > 0:
			s.data = append(s.data, dataItem{file: v[at+1:], encode: v[:at]})
		default:
			s.data = append(s.data, dataItem{value: curlEscape(v)})
		}
	}
}

// curlEscape percent-encodes everything except RFC 3986 unreserved bytes,
// like curl_easy_escape.
func curlEscape(v string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&15])
	}
	return sb.String()
}

// addForm parses a -F value: name=value, name=@file;type=..;filename=..,
// name=<file, with optional quoting of the value.
func (s *state) addForm(v string, literal bool) error {
	eq := strings.IndexByte(v, '=')
	if eq <= 0 {
		return fmt.Errorf("-F %q: expected name=content", v)
	}
	it := formItem{name: v[:eq]}
	rest := v[eq+1:]
	if literal {
		it.value = rest
		s.forms = append(s.forms, it)
		return nil
	}
	isFile, fromContent := false, false
	switch {
	case strings.HasPrefix(rest, "@"):
		isFile, rest = true, rest[1:]
	case strings.HasPrefix(rest, "<"):
		fromContent, rest = true, rest[1:]
	}
	main, params := splitFormParams(rest)
	for _, p := range params {
		k, val, _ := strings.Cut(p, "=")
		val = unquoteParam(val)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "type":
			it.ctype = val
		case "filename":
			it.filename = val
		case "headers":
			if it.headers == nil {
				it.headers = map[string]string{}
			}
			if hn, hv, ok := strings.Cut(val, ":"); ok {
				it.headers[strings.TrimSpace(hn)] = strings.TrimSpace(hv)
			}
		case "encoder":
			s.warn("-F %s: encoder= is not supported", it.name)
		default:
			// Not a recognised parameter: it was part of the value.
			if !isFile && !fromContent {
				main += ";" + p
			}
		}
	}
	switch {
	case isFile:
		if main == "-" {
			s.warn("-F %s=@-: reading from stdin is not supported", it.name)
			return nil
		}
		it.isFile, it.file = true, main
	case fromContent:
		it.fromContent, it.file = true, main
		s.warn("-F %s=<%s: sent as a file part (with a filename); curl sends the content as a plain field", it.name, main)
	default:
		it.value = main
	}
	s.forms = append(s.forms, it)
	return nil
}

// splitFormParams splits "content;type=x;filename=y" honouring a quoted
// content ("a;b";type=x).
func splitFormParams(v string) (string, []string) {
	var main string
	rest := v
	if strings.HasPrefix(v, `"`) {
		if end := strings.Index(v[1:], `"`); end >= 0 {
			main = strings.ReplaceAll(v[1:end+1], `\"`, `"`)
			rest = v[end+2:]
			rest = strings.TrimPrefix(rest, ";")
			if rest == "" {
				return main, nil
			}
			return main, strings.Split(rest, ";")
		}
	}
	parts := strings.Split(rest, ";")
	return parts[0], parts[1:]
}

func unquoteParam(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`)
	}
	return v
}

// build assembles the tool arguments.
func (s *state) build() (*Result, error) {
	if len(s.urls) == 0 {
		return nil, errors.New("no URL found in the curl command")
	}
	if len(s.urls) > 1 {
		s.warn("several URLs given; only the first (%s) is converted", s.urls[0])
	}
	rawURL := s.urls[0]
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	// Headers (ordered, merged by name, removals applied).
	hmap := map[string]string{}
	hnames := map[string]string{} // lower -> display name
	for _, h := range s.headers {
		k := strings.ToLower(h.name)
		if h.value == "\x00remove" {
			delete(hmap, k)
			delete(hnames, k)
			continue
		}
		if old, ok := hmap[k]; ok && old != "" {
			sep := ", "
			if k == "cookie" {
				sep = "; "
			}
			hmap[k] = old + sep + h.value
		} else {
			hmap[k] = h.value
		}
		hnames[k] = h.name
	}
	if s.compressed && hmap["accept-encoding"] == "" {
		hmap["accept-encoding"], hnames["accept-encoding"] = "gzip, deflate", "Accept-Encoding"
		s.warn("--compressed: brotli/zstd are not decoded; requesting gzip and deflate only")
	}
	if s.jsonMode {
		if _, ok := hmap["content-type"]; !ok {
			hmap["content-type"], hnames["content-type"] = "application/json", "Content-Type"
		}
		if _, ok := hmap["accept"]; !ok {
			hmap["accept"], hnames["accept"] = "application/json", "Accept"
		}
	}

	args := map[string]any{}
	tool := ToolRequest

	// Body: join data items.
	var dataStr string
	var dataFile string
	hasData := len(s.data) > 0
	if hasData {
		var pieces []string
		for _, d := range s.data {
			if d.file != "" {
				if len(s.data) == 1 && !s.get {
					dataFile = d.file
					if d.strips {
						s.warn("-d @%s: curl strips newlines from the file; the file is sent unchanged (use --data-binary semantics)", d.file)
					}
					if d.encode != "" {
						s.warn("--data-urlencode @%s: the file is sent as-is, not URL-encoded", d.file)
						if d.encode != "\x00" {
							s.warn("--data-urlencode %s@%s: the field name is dropped", d.encode, d.file)
						}
					}
					continue
				}
				s.warn("data from file %s cannot be combined with other data; it was dropped", d.file)
				continue
			}
			pieces = append(pieces, d.value)
		}
		dataStr = strings.Join(pieces, "&")
	}

	method := strings.ToUpper(s.method)
	if s.get && hasData {
		if dataStr != "" {
			if strings.Contains(rawURL, "?") {
				rawURL += "&" + dataStr
			} else {
				rawURL += "?" + dataStr
			}
		}
		hasData = false
		dataFile = ""
	}

	switch {
	case s.upload != "":
		tool = ToolUpload
		args["file"] = s.upload
		if method == "" {
			method = "PUT"
		}
		if hasData || len(s.forms) > 0 {
			s.warn("-T/--upload-file takes precedence; data and form options were dropped")
		}
		if method != "PUT" {
			args["method"] = method
		}
		if ct, ok := hmap["content-type"]; ok {
			args["content_type"] = ct
			delete(hmap, "content-type")
		}
		if s.retries > 0 {
			args["retries"] = s.retries
		}
	case len(s.forms) > 0:
		tool = ToolMultipart
		if hasData {
			s.warn("-d and -F cannot be combined; data was dropped")
		}
		if ct, ok := hmap["content-type"]; ok {
			if !strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
				s.warn("Content-Type %q replaced by multipart/form-data", ct)
			}
			delete(hmap, "content-type") // the tool sets it with its own boundary
		}
		if method != "" && method != "POST" {
			args["method"] = method
		}
		var parts []map[string]any
		for _, f := range s.forms {
			p := map[string]any{"name": f.name}
			if f.isFile || f.fromContent {
				p["file"] = f.file
				if f.filename != "" {
					p["filename"] = f.filename
				}
			} else {
				p["value"] = f.value
				if f.filename != "" {
					p["filename"] = f.filename
				}
			}
			if f.ctype != "" {
				p["content_type"] = f.ctype
			}
			if len(f.headers) > 0 {
				p["headers"] = f.headers
			}
			parts = append(parts, p)
		}
		args["parts"] = parts
	case hasData && dataFile == "" && isFormContentType(hmap) && looksLikeForm(dataStr):
		tool = ToolForm
		delete(hmap, "content-type")
		if method != "" && method != "POST" {
			args["method"] = method
		}
		args["fields"] = formFields(dataStr)
	default:
		if method == "" {
			switch {
			case s.head:
				method = "HEAD"
			case hasData:
				method = "POST"
			default:
				method = "GET"
			}
		}
		args["method"] = method
		if hasData {
			if dataFile != "" {
				args["body_file"] = dataFile
			} else {
				args["body"] = dataStr
			}
			if _, ok := hmap["content-type"]; !ok {
				hmap["content-type"], hnames["content-type"] = "application/x-www-form-urlencoded", "Content-Type"
			}
		}
	}
	if s.head && method != "" && method != "HEAD" {
		s.warn("-I/--head ignored because the method is %s", method)
	}

	args["url"] = rawURL
	if len(hmap) > 0 {
		hs := map[string]string{}
		keys := make([]string, 0, len(hmap))
		for k := range hmap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			hs[hnames[k]] = hmap[k]
		}
		args["headers"] = hs
	}

	if a := s.authArg(); a != nil {
		args["auth"] = a
	}
	if s.insecure {
		args["insecure_skip_verify"] = true
	}
	if s.location != nil {
		args["follow_redirects"] = *s.location
	}
	if s.maxRedirs > 0 {
		args["max_redirects"] = s.maxRedirs
	}
	switch {
	case s.maxTime > 0:
		args["timeout_seconds"] = s.maxTime
	case s.connTimeout > 0:
		s.warn("--connect-timeout applies to the whole request (timeout_seconds)")
		args["timeout_seconds"] = s.connTimeout
	}
	if s.proxy != "" {
		p := s.proxy
		if !strings.Contains(p, "://") {
			p = "http://" + p
		}
		if s.proxyUser != "" {
			if pu, err := url.Parse(p); err == nil {
				user, pass, _ := strings.Cut(s.proxyUser, ":")
				pu.User = url.UserPassword(user, pass)
				p = pu.String()
			}
		}
		args["proxy"] = p
	}
	if s.httpVersion != "" {
		args["http_version"] = s.httpVersion
	}
	if s.cacert != "" {
		args["ca_cert"] = s.cacert
	}
	if s.cert != "" {
		args["client_cert"] = s.cert
		if s.key != "" {
			args["client_key"] = s.key
		} else {
			s.warn("--cert without --key: client_key must be set (combined PEM files are not split automatically)")
		}
	}
	if s.retries > 0 && tool != ToolUpload {
		s.warn("--retry is only supported by http_upload; ignored")
	}

	save := s.output
	if save == "" && s.remoteName {
		if u, err := url.Parse(rawURL); err == nil {
			save = path.Base(u.Path)
		}
		if save == "" || save == "/" || save == "." {
			s.warn("-O: the URL has no file name; set save_to explicitly")
			save = ""
		}
	}
	if save == "-" {
		save = ""
	}
	if save != "" {
		if tool == ToolUpload {
			s.warn("-o is not supported with -T; the response is returned inline")
		} else {
			args["save_to"] = save
		}
	}
	return &Result{Tool: tool, Arguments: args, Warnings: s.warnings}, nil
}

func (s *state) authArg() map[string]any {
	user, pass, _ := strings.Cut(s.user, ":")
	switch {
	case s.awsSigV4 != "":
		// --aws-sigv4 "aws:amz:region:service" with -u key:secret.
		parts := strings.Split(s.awsSigV4, ":")
		aws := map[string]any{"access_key_id": user, "secret_access_key": pass}
		if len(parts) >= 3 {
			aws["region"] = parts[2]
		}
		if len(parts) >= 4 {
			aws["service"] = parts[3]
		}
		if len(parts) < 4 {
			s.warn("--aws-sigv4 %q: set aws.region and aws.service", s.awsSigV4)
		}
		return map[string]any{"type": "aws_sigv4", "aws": aws}
	case s.bearer != "":
		return map[string]any{"type": "bearer", "token": s.bearer}
	case s.hasUser:
		if !strings.Contains(s.user, ":") {
			s.warn("-u %s has no password (curl would prompt); password left empty", user)
		}
		t := s.authType
		if t == "" {
			t = "basic"
		}
		a := map[string]any{"type": t, "username": user, "password": pass}
		if t == "ntlm" {
			if d, u, ok := strings.Cut(user, `\`); ok {
				a["domain"], a["username"] = d, u
			}
		}
		return a
	case s.authType == "negotiate":
		s.warn("--negotiate needs auth.kerberos settings (realm, keytab or password)")
		return map[string]any{"type": "negotiate"}
	}
	return nil
}

func isFormContentType(h map[string]string) bool {
	ct, ok := h["content-type"]
	if !ok {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/x-www-form-urlencoded")
}

// looksLikeForm reports whether data is a&b=c style form data that
// survives decoding and re-encoding unchanged in meaning.
func looksLikeForm(data string) bool {
	if data == "" {
		return false
	}
	for _, p := range strings.Split(data, "&") {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return false
		}
		if _, err := url.QueryUnescape(k); err != nil {
			return false
		}
		if _, err := url.QueryUnescape(v); err != nil {
			return false
		}
	}
	return true
}

func formFields(data string) []map[string]any {
	var out []map[string]any
	for _, p := range strings.Split(data, "&") {
		k, v, _ := strings.Cut(p, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		out = append(out, map[string]any{"name": k, "value": v})
	}
	return out
}
