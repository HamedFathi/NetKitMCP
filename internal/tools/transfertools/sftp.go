package transfertools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/transfer"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/sftpx"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const sftpAuthHelp = `auth.type ssh_password (auth.username, auth.password) or ssh_key (auth.username, auth.ssh.private_key, optional auth.ssh.passphrase); host key verification via auth.ssh.known_hosts or auth.ssh.host_key_fingerprint (or explicitly auth.ssh.insecure_ignore_host_key=true)`

type sftpConnIn struct {
	Host string       `json:"host" jsonschema:"SFTP server host name or IP"`
	Port int          `json:"port,omitempty" jsonschema:"SSH port (default 22)"`
	Auth *auth.Config `json:"auth" jsonschema:"SSH credentials and host-key verification"`
	connOptions
}

type sftpUploadIn struct {
	sftpConnIn
	File       string `json:"file" jsonschema:"path of the local file to upload (inside an allowed read directory)"`
	RemotePath string `json:"remote_path" jsonschema:"remote file path; a trailing / uploads into that directory with the local file name"`
	Mkdirs     bool   `json:"mkdirs,omitempty" jsonschema:"create missing remote parent directories"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"replace an existing remote file (default: fail if it exists)"`
	Preserve   bool   `json:"preserve,omitempty" jsonschema:"copy the local permission bits and modification time to the remote file"`
}

type sftpDownloadIn struct {
	sftpConnIn
	RemotePath string `json:"remote_path" jsonschema:"remote file to download"`
	SaveTo     string `json:"save_to" jsonschema:"local destination path (inside an allowed write directory)"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"replace an existing local file"`
	Resume     bool   `json:"resume,omitempty" jsonschema:"continue a partial download: keep the bytes already in save_to and fetch the rest"`
}

type sftpListIn struct {
	sftpConnIn
	Path       string `json:"path,omitempty" jsonschema:"remote directory (default: the login directory)"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"descend into subdirectories (bounded by max_depth and max_entries)"`
	MaxDepth   int    `json:"max_depth,omitempty" jsonschema:"maximum depth when recursive (default 5, max 20)"`
	MaxEntries int    `json:"max_entries,omitempty" jsonschema:"maximum entries returned (default 1000, max 10000)"`
}

type listOut struct {
	Host      string         `json:"host"`
	Path      string         `json:"path"`
	Entries   any            `json:"entries"`
	Count     int            `json:"count"`
	Truncated bool           `json:"truncated"`
	Meta      map[string]any `json:"meta,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

func registerSFTP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "sftp_upload", "SFTP upload",
		"Upload a local file to an SFTP server (streamed, concurrent writes). Requires "+sftpAuthHelp+
			". Fails if the remote file exists unless overwrite=true; mkdirs creates parent directories. Every result reports the server's host key fingerprint so it can be pinned.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sftpUploadIn) (any, error) {
			return runSFTPUpload(ctx, req, d, in)
		})
	tools.Add(s, d, "sftp_download", "SFTP download",
		"Download a remote file from an SFTP server to save_to (streamed to disk, never returned inline). Requires "+sftpAuthHelp+
			". Will not replace an existing local file unless overwrite=true; resume=true continues a partial download.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in sftpDownloadIn) (any, error) {
			return runSFTPDownload(ctx, req, d, in)
		})
	tools.Add(s, d, "sftp_list", "SFTP list",
		"List a remote directory on an SFTP server: name, size, mode, mtime, is_dir and symlink target. recursive=true walks subdirectories within max_depth/max_entries. Requires "+sftpAuthHelp+".",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in sftpListIn) (any, error) {
			return runSFTPList(ctx, d, in)
		})
}

func sshCredentials(d *tools.Deps, a *auth.Config) (sftpx.Credentials, sftpx.HostKeyPolicy, error) {
	var cr sftpx.Credentials
	var hk sftpx.HostKeyPolicy
	if a == nil {
		return cr, hk, errors.New("auth is required for SFTP: " + sftpAuthHelp)
	}
	cr.Username = a.Username
	switch a.Kind() {
	case "ssh_password", "basic":
		if a.Password == "" {
			return cr, hk, errors.New("auth.password is required for ssh_password")
		}
		cr.Password = a.Password
	case "ssh_key":
		if a.SSH == nil || a.SSH.PrivateKey == "" {
			return cr, hk, errors.New("auth.ssh.private_key is required for ssh_key (inline PEM/OpenSSH key or a file path)")
		}
		key, err := auth.LoadKey(d.AuthEnv(false), a.SSH.PrivateKey)
		if err != nil {
			return cr, hk, fmt.Errorf("auth.ssh.private_key: %w", err)
		}
		cr.PrivateKey = key
		cr.Passphrase = a.SSH.Passphrase
		cr.Password = a.Password
	default:
		return cr, hk, fmt.Errorf("auth type %q is not supported for SFTP: use %s", a.Kind(), sftpAuthHelp)
	}
	if cr.Username == "" {
		return cr, hk, errors.New("auth.username is required for SFTP")
	}
	if s := a.SSH; s != nil {
		hk.Fingerprint = s.HostKeyFingerprint
		hk.Insecure = s.InsecureIgnoreHostKey
		if s.KnownHosts != "" {
			if sftpx.LooksLikeKnownHosts(s.KnownHosts) {
				hk.KnownHosts = []byte(s.KnownHosts)
			} else {
				data, err := d.Files.ReadSmall(s.KnownHosts, 8<<20)
				if err != nil {
					return cr, hk, fmt.Errorf("auth.ssh.known_hosts: %w", err)
				}
				hk.KnownHosts = data
			}
		}
	}
	return cr, hk, nil
}

func connectSFTP(ctx context.Context, d *tools.Deps, in sftpConnIn) (*sftpx.Client, error) {
	if in.Host == "" {
		return nil, errors.New("host is required")
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	cr, hk, err := sshCredentials(d, in.Auth)
	if err != nil {
		return nil, err
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	dialer := d.Guard.Dialer(in.AllowPrivate, timeout)
	return sftpx.Connect(ctx, sftpx.Config{
		Addr:        net.JoinHostPort(in.Host, strconv.Itoa(port)),
		Credentials: cr,
		HostKey:     hk,
		Dial:        dialer.DialContext,
		Timeout:     timeout,
		Idle:        timeout,
	})
}

func sftpMeta(c *sftpx.Client, out map[string]any) []string {
	out["host_key"] = c.HostKey
	out["server_version"] = c.ServerVersion
	if c.HostKey.VerifiedBy == "insecure_ignore_host_key" {
		return []string{"SSH host key verification was skipped (insecure_ignore_host_key); pin host_key_fingerprint " + c.HostKey.FingerprintSHA256 + " to verify it next time"}
	}
	return nil
}

func runSFTPUpload(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in sftpUploadIn) (any, error) {
	start := time.Now()
	src, err := openSource(d, in.File)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	c, err := connectSFTP(ctx, d, in.sftpConnIn)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	remote := remoteTarget(in.RemotePath, src.name)
	if fi, err := c.Stat(remote); err == nil && fi.IsDir() {
		remote = path.Join(remote, src.name)
	}
	if in.Mkdirs {
		if dir := path.Dir(remote); dir != "." && dir != "/" {
			if err := c.MkdirAll(dir); err != nil {
				return nil, fmt.Errorf("creating remote directory %s: %w", dir, err)
			}
		}
	}
	if fi, err := c.Stat(remote); err == nil {
		if fi.IsDir() {
			return nil, fmt.Errorf("remote path %s is a directory", remote)
		}
		if !in.Overwrite {
			return nil, fmt.Errorf("remote file %s already exists (%d bytes); set overwrite=true to replace it", remote, fi.Size())
		}
	}
	rf, err := c.OpenFile(remote, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		if !in.Mkdirs {
			return nil, fmt.Errorf("opening remote file %s: %w (set mkdirs=true if the directory is missing)", remote, err)
		}
		return nil, fmt.Errorf("opening remote file %s: %w", remote, err)
	}
	rep := progress.FromRequest(req)
	size := src.info.Size()
	hr := fileio.NewHashingReader(&progressReader{r: src.f, total: size, fn: rep.Func(ctx, "sftp upload "+src.name)})
	n, err := rf.ReadFromWithConcurrency(hr, 0)
	cerr := rf.Close()
	if err != nil {
		return nil, ctxErr(ctx, fmt.Errorf("uploading to %s after %d bytes: %w", remote, n, err))
	}
	if cerr != nil {
		return nil, fmt.Errorf("closing remote file %s: %w", remote, cerr)
	}
	out := newResult()
	out.Warnings = sftpMeta(c, out.Meta)
	if in.Preserve {
		if err := c.Chmod(remote, src.info.Mode().Perm()); err != nil {
			out.Warnings = append(out.Warnings, "could not set remote mode: "+err.Error())
		}
		if err := c.Chtimes(remote, src.info.ModTime(), src.info.ModTime()); err != nil {
			out.Warnings = append(out.Warnings, "could not set remote mtime: "+err.Error())
		}
	}
	if fi, err := c.Stat(remote); err == nil && fi.Size() != hr.N() {
		return nil, fmt.Errorf("remote file %s is %d bytes after upload, expected %d", remote, fi.Size(), hr.N())
	}
	out.File = src.fileInfo(hr.SHA256(), "")
	out.BytesTransferred = hr.N()
	out.Parts = 1
	out.Remote = types.RemoteInfo{Path: remote}
	return finish(out, start), nil
}

func runSFTPDownload(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in sftpDownloadIn) (any, error) {
	start := time.Now()
	if in.RemotePath == "" || in.SaveTo == "" {
		return nil, errors.New("remote_path and save_to are required")
	}
	// Fail fast on a forbidden destination before connecting.
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
	c, err := connectSFTP(ctx, d, in.sftpConnIn)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	fi, err := c.Stat(in.RemotePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", in.RemotePath, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("remote path %s is a directory (use sftp_list)", in.RemotePath)
	}
	size := fi.Size()
	maxDl := d.Cfg.DownloadBytes(0)
	if size > maxDl {
		return nil, fmt.Errorf("remote file is %d bytes, above the %d byte download limit", size, maxDl)
	}
	var offset int64
	if partial > 0 {
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
	rf, err := c.Open(in.RemotePath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", in.RemotePath, err)
	}
	defer rf.Close()
	if offset > 0 {
		if _, err := rf.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seeking %s to %d: %w", in.RemotePath, offset, err)
		}
	}
	rep := progress.FromRequest(req)
	cw := &transfer.CountingWriter{W: w, Base: offset, Total: size, Progress: rep.Func(ctx, "sftp download "+in.RemotePath)}
	if _, err := rf.WriteTo(cw); err != nil {
		return nil, ctxErr(ctx, fmt.Errorf("downloading %s after %d bytes: %w", in.RemotePath, cw.N, err))
	}
	if w.N() != size {
		return nil, fmt.Errorf("downloaded %d bytes but the remote file is %d bytes (it may have changed during the transfer)", w.N(), size)
	}
	info, err := w.Commit()
	if err != nil {
		return nil, err
	}
	out := newResult()
	out.Warnings = sftpMeta(c, out.Meta)
	out.File = info
	out.BytesTransferred = cw.N
	out.ResumedFrom = offset
	out.Parts = 1
	out.Remote = types.RemoteInfo{Path: in.RemotePath}
	out.Meta["remote_mtime"] = fi.ModTime().UTC().Format(time.RFC3339)
	return finish(out, start), nil
}

func listBounds(recursive bool, depth, entries int) (int, int) {
	if depth <= 0 {
		depth = 5
	}
	depth = min(depth, 20)
	if !recursive {
		depth = 1
	}
	if entries <= 0 {
		entries = 1000
	}
	return depth, min(entries, 10000)
}

func runSFTPList(ctx context.Context, d *tools.Deps, in sftpListIn) (any, error) {
	c, err := connectSFTP(ctx, d, in.sftpConnIn)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	p := in.Path
	if p == "" {
		p = "."
	}
	depth, maxEntries := listBounds(in.Recursive, in.MaxDepth, in.MaxEntries)
	entries, truncated, err := c.List(ctx, p, sftpx.ListOptions{Recursive: in.Recursive, MaxDepth: depth, MaxEntries: maxEntries})
	if err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []sftpx.Entry{}
	}
	out := &listOut{Host: in.Host, Path: p, Entries: entries, Count: len(entries), Truncated: truncated, Meta: map[string]any{}}
	out.Warnings = sftpMeta(c, out.Meta)
	if truncated {
		out.Warnings = append(out.Warnings, fmt.Sprintf("listing stopped at %d entries (raise max_entries or narrow path)", maxEntries))
	}
	return out, nil
}
