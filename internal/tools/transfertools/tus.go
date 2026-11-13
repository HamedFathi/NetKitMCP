package transfertools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/transfer"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/tus"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const maxTusChunk = 256 << 20

type tusIn struct {
	URL                string            `json:"url,omitempty" jsonschema:"tus creation endpoint (POST target), e.g. https://host/files/; required unless upload_url is set"`
	UploadURL          string            `json:"upload_url,omitempty" jsonschema:"resume an upload created earlier (the upload_url from a previous result or error)"`
	File               string            `json:"file" jsonschema:"path of the file to upload (inside an allowed read directory)"`
	ChunkSize          int64             `json:"chunk_size,omitempty" jsonschema:"bytes per PATCH request (default 8 MiB, max 256 MiB)"`
	Filename           string            `json:"filename,omitempty" jsonschema:"filename sent in Upload-Metadata (default: the local file name)"`
	ContentType        string            `json:"content_type,omitempty" jsonschema:"filetype sent in Upload-Metadata (default: detected from the extension)"`
	Metadata           map[string]string `json:"metadata,omitempty" jsonschema:"extra Upload-Metadata key/values (values are base64-encoded for you)"`
	Headers            map[string]string `json:"headers,omitempty" jsonschema:"extra HTTP headers for every request"`
	CreationWithUpload bool              `json:"creation_with_upload,omitempty" jsonschema:"send the first chunk in the creation POST (creation-with-upload extension)"`
	Checksum           bool              `json:"checksum,omitempty" jsonschema:"send Upload-Checksum (sha1) with each chunk when the server supports the checksum extension"`
	MaxRetries         *int              `json:"max_retries,omitempty" jsonschema:"retries per chunk on network errors / 5xx / offset conflicts, with backoff (default 3)"`
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty"`
}

func registerTus(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "tus_upload", "tus resumable upload",
		"Upload a local file with the tus 1.0 resumable protocol: discovers capabilities (OPTIONS), creates the upload (POST) and sends it in PATCH chunks with per-chunk retries. "+
			"The result (and any error) includes upload_url: pass it back as upload_url to resume an interrupted upload from the server's offset. "+
			"timeout_seconds applies per HTTP request (each chunk). Auth and the SSRF guard apply.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in tusIn) (any, error) {
			return runTus(ctx, req, d, in)
		})
}

func runTus(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in tusIn) (any, error) {
	start := time.Now()
	if in.URL == "" && in.UploadURL == "" {
		return nil, errors.New("set url (the tus creation endpoint) or upload_url (to resume)")
	}
	for _, raw := range []string{in.URL, in.UploadURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid URL %q: want http(s)://host/path", raw)
		}
	}
	chunk := in.ChunkSize
	if chunk <= 0 {
		chunk = tus.DefaultChunkSize
	}
	if chunk > maxTusChunk {
		chunk = maxTusChunk
	}
	retries := 3
	if in.MaxRetries != nil {
		retries = *in.MaxRetries
		if retries < 0 {
			retries = 0
		}
		if retries > 20 {
			retries = 20
		}
	}
	src, err := openSource(d, in.File)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	md := map[string]string{}
	for k, v := range in.Metadata {
		if !tus.ValidMetadataKey(k) {
			return nil, fmt.Errorf("metadata key %q is invalid (ASCII without spaces or commas)", k)
		}
		md[k] = v
	}
	name := in.Filename
	if name == "" {
		name = src.name
	}
	ctype := in.ContentType
	if ctype == "" {
		ctype = fileio.DetectContentType(src.name, nil)
	}
	if _, ok := md["filename"]; !ok {
		md["filename"] = name
	}
	if _, ok := md["filetype"]; !ok {
		md["filetype"] = ctype
	}

	c, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	hasher := transfer.NewSeqHasher(src.f)
	rep := progress.FromRequest(req)
	opts := tus.Options{
		Client:             c.Client,
		UserAgent:          c.UserAgent(),
		Endpoint:           in.URL,
		UploadURL:          in.UploadURL,
		File:               src.f,
		Size:               src.info.Size(),
		Metadata:           md,
		Headers:            tools.Headers(in.Headers),
		ChunkSize:          chunk,
		CreationWithUpload: in.CreationWithUpload,
		Checksum:           in.Checksum,
		MaxRetries:         retries,
		RequestTimeout:     c.Timeout,
		Observe:            hasher.Feed,
		Progress:           rep.Func(ctx, "tus upload "+src.name),
	}
	res, err := tus.Upload(ctx, opts)
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	sum, err := hasher.Finish(src.info.Size())
	if err != nil {
		return nil, fmt.Errorf("hashing %s: %w", src.name, err)
	}
	out := newResult()
	out.File = src.fileInfo(sum, ctype)
	out.BytesTransferred = res.BytesSent
	out.ResumedFrom = res.ResumedFrom
	out.Parts = res.Chunks
	out.Remote = types.RemoteInfo{Status: res.LastStatus, Location: res.UploadURL}
	out.Meta["upload_url"] = res.UploadURL
	out.Meta["offset"] = res.Offset
	out.Meta["chunk_size"] = chunk
	out.Meta["requests"] = res.Requests
	out.Meta["retries"] = res.Retries
	out.Meta["created"] = res.Created
	out.Meta["checksum_sent"] = res.ChecksumsSent
	out.Meta["server"] = res.Server
	out.Warnings = append(out.Warnings, res.Warnings...)
	if c.Insecure {
		out.Warnings = append(out.Warnings, "TLS certificate verification was disabled (insecure_skip_verify)")
	}
	return finish(out, start), nil
}
