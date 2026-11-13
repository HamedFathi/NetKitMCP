package httptools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

func init() { tools.RegisterGroup(tools.GroupHTTP, register) }

func register(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "http_request", "HTTP request",
		"Send an HTTP request with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, PROPFIND, REPORT, PURGE, ...). "+
			"Body: one of body (text), json, body_base64 (small) or body_file (streamed from disk). "+
			"Supports query params, headers, auth, HTTP/1.1, 2 or 3 (http_version), redirects, proxy and TLS options. "+
			"Large responses are truncated to max_response_bytes (default 1 MiB); use save_to to stream a download to disk (reports size and sha256). "+
			"Private/loopback targets need allow_private=true.",
		tools.Mutating, handleRequest(d))
	tools.Add(s, d, "http_form_request", "HTTP form request",
		"Send an application/x-www-form-urlencoded form (default POST). fields is a list of {name, value} (order kept, repeated names allowed) "+
			"or an object of name -> string or list. Same transport, auth and save_to options as http_request.",
		tools.Mutating, handleForm(d))
	tools.Add(s, d, "http_multipart_request", "HTTP multipart request",
		"Send multipart/form-data (default POST): text fields plus parts that are text (value), JSON (json), files streamed from disk (file) or small binary (base64). "+
			"Repeat a part name for several files in one field; set filename, content_type and headers per part. "+
			"Files are streamed, never buffered, and Content-Length is computed up front. Reports name, size and sha256 of each uploaded file.",
		tools.Mutating, handleMultipart(d))
	tools.Add(s, d, "http_upload", "HTTP file upload",
		"Stream a file from disk as a raw PUT (default) or POST body, e.g. to a presigned S3, GCS or Azure Blob URL (no auth needed; add headers like x-ms-blob-type as required). "+
			"Detects the content type, optionally sends an md5/sha256 checksum header, retries on network errors/408/429/5xx (re-reading the file), "+
			"and returns file name/size/sha256, bytes transferred, timing and the remote status/location/etag. Raise timeout_seconds for large files.",
		tools.Mutating, handleUpload(d))
	tools.Add(s, d, "curl_to_request", "Convert curl command",
		"Parse a pasted curl command (bash, cmd ^ or PowerShell ` line continuations) into arguments for http_request, http_form_request, http_multipart_request or http_upload. "+
			"Returns {tool, arguments, warnings}; call the named tool with the arguments. Does not send anything. @file references become file paths that must be inside an allowed read directory.",
		tools.Local, handleCurl(d))
}
