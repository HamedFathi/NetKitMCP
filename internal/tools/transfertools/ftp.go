package transfertools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/transfer"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/ftpx"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type ftpConnIn struct {
	Host        string       `json:"host" jsonschema:"FTP server host name or IP"`
	Port        int          `json:"port,omitempty" jsonschema:"port (default 21, or 990 for implicit TLS)"`
	TLS         string       `json:"tls,omitempty" jsonschema:"none (plain FTP, default), explicit (AUTH TLS upgrade) or implicit (FTPS, TLS from the start)"`
	Auth        *auth.Config `json:"auth,omitempty" jsonschema:"login: type basic with username and password; omit for anonymous login"`
	DisableEPSV bool         `json:"disable_epsv,omitempty" jsonschema:"use PASV instead of EPSV for data connections"`
	TrustPasvIP bool         `json:"trust_pasv_ip,omitempty" jsonschema:"connect data channels to the address in the PASV reply even if it differs from the control host (still SSRF-checked); default uses the control host"`
	types.NetOptions
}

type ftpUploadIn struct {
	ftpConnIn
	File       string `json:"file" jsonschema:"path of the local file to upload (inside an allowed read directory)"`
	RemotePath string `json:"remote_path" jsonschema:"remote file path; a trailing / uploads into that directory with the local file name"`
	Mkdirs     bool   `json:"mkdirs,omitempty" jsonschema:"create missing remote parent directories"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"replace an existing remote file (default: fail if it exists)"`
}

type ftpDownloadIn struct {
	ftpConnIn
	RemotePath string `json:"remote_path" jsonschema:"remote file to download"`
	SaveTo     string `json:"save_to" jsonschema:"local destination path (inside an allowed write directory)"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"replace an existing local file"`
	Resume     bool   `json:"resume,omitempty" jsonschema:"continue a partial download with REST: keep the bytes already in save_to and fetch the rest"`
}

type ftpListIn struct {
	ftpConnIn
	Path       string `json:"path,omitempty" jsonschema:"remote directory (default: the login directory)"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"descend into subdirectories (bounded by max_depth and max_entries)"`
	MaxDepth   int    `json:"max_depth,omitempty" jsonschema:"maximum depth when recursive (default 5, max 20)"`
	MaxEntries int    `json:"max_entries,omitempty" jsonschema:"maximum entries returned (default 1000, max 10000)"`
}

func registerFTP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "ftp_upload", "FTP upload",
		"Upload a local file to an FTP or FTPS server (tls: explicit or implicit), streamed from disk. Fails if the remote file exists unless overwrite=true; mkdirs creates parent directories. "+
			"Login with auth.type=basic or anonymously. timeout_seconds bounds connecting and inactivity.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in ftpUploadIn) (any, error) {
			return runFTPUpload(ctx, req, d, in)
		})
	tools.Add(s, d, "ftp_download", "FTP download",
		"Download a file from an FTP or FTPS server to save_to (streamed to disk, never returned inline). Will not replace an existing local file unless overwrite=true; resume=true continues a partial download (REST).",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in ftpDownloadIn) (any, error) {
			return runFTPDownload(ctx, req, d, in)
		})
	tools.Add(s, d, "ftp_list", "FTP list",
		"List a directory on an FTP or FTPS server (MLSD when supported, falling back to LIST): name, type, size, mtime, symlink target. recursive=true walks subdirectories within max_depth/max_entries.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in ftpListIn) (any, error) {
			return runFTPList(ctx, d, in)
		})
}

func ftpConfig(d *tools.Deps, in ftpConnIn) (ftpx.Config, error) {
	var cfg ftpx.Config
	if in.Host == "" {
		return cfg, errors.New("host is required")
	}
	if !ftpx.ValidMode(in.TLS) {
		return cfg, fmt.Errorf("tls must be none, explicit or implicit (got %q)", in.TLS)
	}
	if in.Port < 0 || in.Port > 65535 {
		return cfg, fmt.Errorf("invalid port %d", in.Port)
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	dialer := d.Guard.Dialer(in.AllowPrivate, timeout)
	cfg = ftpx.Config{
		Host:        strings.Trim(in.Host, "[]"),
		Port:        in.Port,
		TLSMode:     in.TLS,
		Dial:        dialer.DialContext,
		TrustPasvIP: in.TrustPasvIP,
		DisableEPSV: in.DisableEPSV,
		Timeout:     timeout,
		Idle:        timeout,
	}
	switch k := in.Auth.Kind(); k {
	case "none":
	case "basic":
		cfg.User, cfg.Password = in.Auth.Username, in.Auth.Password
		if cfg.User == "" {
			return cfg, errors.New("auth.username is required for basic auth (omit auth for anonymous login)")
		}
	default:
		return cfg, fmt.Errorf("auth type %q is not supported for FTP; use auth.type=basic with username/password, or omit auth for anonymous", k)
	}
	if in.TLS != "" && in.TLS != ftpx.TLSNone {
		tc, err := tlsx.Config(d.Files, in.TLSOptions, cfg.Host, nil)
		if err != nil {
			return cfg, err
		}
		cfg.TLS = tc
	}
	return cfg, nil
}

func connectFTP(ctx context.Context, d *tools.Deps, in ftpConnIn) (*ftpx.Conn, error) {
	cfg, err := ftpConfig(d, in)
	if err != nil {
		return nil, err
	}
	return ftpx.Connect(ctx, cfg)
}

func ftpMeta(c *ftpx.Conn, in ftpConnIn, meta map[string]any) []string {
	meta["tls"] = c.TLSMode()
	meta["data_connections"] = c.DataConns()
	var w []string
	if c.TLSMode() != ftpx.TLSNone && in.InsecureSkipVerify {
		w = append(w, "TLS certificate verification was disabled (insecure_skip_verify)")
	}
	if c.TLSMode() == ftpx.TLSNone && in.Auth.Kind() == "basic" {
		w = append(w, "credentials were sent unencrypted (plain FTP); use tls=explicit or implicit if the server supports it")
	}
	return w
}

func runFTPUpload(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in ftpUploadIn) (any, error) {
	start := time.Now()
	src, err := openSource(d, in.File)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	c, err := connectFTP(ctx, d, in.ftpConnIn)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	remote := remoteTarget(in.RemotePath, src.name)
	if in.Mkdirs {
		if dir := path.Dir(remote); dir != "." && dir != "/" {
			c.MkdirAll(dir)
		}
	}
	if exists, n := c.Exists(remote); exists && !in.Overwrite {
		return nil, fmt.Errorf("remote file %s already exists (%d bytes); set overwrite=true to replace it", remote, n)
	}
	rep := progress.FromRequest(req)
	size := src.info.Size()
	hr := fileio.NewHashingReader(&progressReader{r: src.f, total: size, fn: rep.Func(ctx, "ftp upload "+src.name)})
	if err := c.Stor(remote, hr); err != nil {
		hint := ""
		if !in.Mkdirs {
			hint = " (set mkdirs=true if the directory is missing)"
		}
		return nil, ctxErr(ctx, fmt.Errorf("STOR %s after %d bytes: %w%s", remote, hr.N(), err, hint))
	}
	out := newResult()
	out.Warnings = ftpMeta(c, in.ftpConnIn, out.Meta)
	if n, err := c.FileSize(remote); err == nil {
		if n != hr.N() {
			return nil, fmt.Errorf("remote file %s is %d bytes after upload, expected %d", remote, n, hr.N())
		}
	} else {
		out.Warnings = append(out.Warnings, "could not verify the remote size (SIZE failed: "+err.Error()+")")
	}
	out.File = src.fileInfo(hr.SHA256(), "")
	out.BytesTransferred = hr.N()
	out.Parts = 1
	out.Remote = types.RemoteInfo{Path: remote}
	return finish(out, start), nil
}

func runFTPDownload(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in ftpDownloadIn) (any, error) {
	start := time.Now()
	if in.RemotePath == "" || in.SaveTo == "" {
		return nil, errors.New("remote_path and save_to are required")
	}
	overwrite := in.Overwrite
	partial := int64(-1)
	if in.Resume {
		partial = partialLocal(d, in.SaveTo)
		if partial >= 0 {
			overwrite = true
		}
	}
	if _, err := d.Files.ResolveWrite(in.SaveTo, overwrite); err != nil {
		return nil, err
	}
	c, err := connectFTP(ctx, d, in.ftpConnIn)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	maxDl := d.Cfg.DownloadBytes(0)
	size, serr := c.FileSize(in.RemotePath)
	if serr != nil {
		size = -1
	}
	if size > maxDl {
		return nil, fmt.Errorf("remote file is %d bytes, above the %d byte download limit", size, maxDl)
	}
	var offset int64
	if partial > 0 {
		if size < 0 {
			return nil, fmt.Errorf("cannot resume: the server did not report the remote size (SIZE failed: %v)", serr)
		}
		if partial > size {
			return nil, fmt.Errorf("local file is %d bytes, larger than the remote file (%d); cannot resume (set resume=false and overwrite=true)", partial, size)
		}
		offset = partial
	}
	w, err := d.Files.CreateWrite(in.SaveTo, overwrite, maxDl)
	if err != nil {
		return nil, err
	}
	defer w.Abort()
	if offset > 0 {
		if err := preparePartial(d, in.SaveTo, w, offset); err != nil {
			return nil, err
		}
	}
	rep := progress.FromRequest(req)
	cw := &transfer.CountingWriter{W: w, Base: offset, Total: size, Progress: rep.Func(ctx, "ftp download "+in.RemotePath)}
	if size < 0 || offset < size || size == 0 {
		resp, err := c.RetrFrom(in.RemotePath, uint64(offset))
		if err != nil {
			return nil, ctxErr(ctx, fmt.Errorf("RETR %s: %w", in.RemotePath, err))
		}
		_, cpErr := io.Copy(cw, resp)
		clErr := resp.Close()
		if cpErr != nil {
			return nil, ctxErr(ctx, fmt.Errorf("downloading %s after %d bytes: %w", in.RemotePath, cw.N, cpErr))
		}
		if clErr != nil {
			return nil, fmt.Errorf("RETR %s: %w", in.RemotePath, clErr)
		}
	}
	if size >= 0 && w.N() != size {
		return nil, fmt.Errorf("downloaded %d bytes but the remote file is %d bytes (it may have changed during the transfer)", w.N(), size)
	}
	info, err := w.Commit()
	if err != nil {
		return nil, err
	}
	out := newResult()
	out.Warnings = ftpMeta(c, in.ftpConnIn, out.Meta)
	out.File = info
	out.BytesTransferred = cw.N
	out.ResumedFrom = offset
	out.Parts = 1
	out.Remote = types.RemoteInfo{Path: in.RemotePath}
	return finish(out, start), nil
}

func runFTPList(ctx context.Context, d *tools.Deps, in ftpListIn) (any, error) {
	cfg, err := ftpConfig(d, in.ftpConnIn)
	if err != nil {
		return nil, err
	}
	c, err := ftpx.Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	depth, maxEntries := listBounds(in.Recursive, in.MaxDepth, in.MaxEntries)
	lo := ftpx.ListOptions{Recursive: in.Recursive, MaxDepth: depth, MaxEntries: maxEntries}
	res, err := c.List(ctx, in.Path, lo)
	var warnings []string
	if errors.Is(err, ftpx.ErrMLSDFailed) {
		c.Close()
		cfg.DisableMLSD = true
		if c, err = ftpx.Connect(ctx, cfg); err != nil {
			return nil, fmt.Errorf("MLSD failed and reconnecting to list with LIST failed: %w", err)
		}
		res, err = c.List(ctx, in.Path, lo)
		warnings = append(warnings, "MLSD failed; listed with LIST instead (times and types may be less precise)")
	}
	if err != nil {
		return nil, err
	}
	entries := res.Entries
	if entries == nil {
		entries = []ftpx.Entry{}
	}
	p := in.Path
	if p == "" {
		p = "."
	}
	out := &listOut{Host: in.Host, Path: p, Entries: entries, Count: len(entries), Truncated: res.Truncated, Meta: map[string]any{"command": res.Command}}
	out.Warnings = append(ftpMeta(c, in.ftpConnIn, out.Meta), warnings...)
	if res.Truncated {
		out.Warnings = append(out.Warnings, fmt.Sprintf("listing stopped at %d entries (raise max_entries or narrow path)", maxEntries))
	}
	return out, nil
}
