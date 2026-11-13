package transfertools

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// connOptions are the network options of the SSH/FTP tools. timeout_seconds
// bounds connecting and any period of inactivity, not the whole transfer, so
// large files can take as long as they need while stalls still end the call.
type connOptions struct {
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty" jsonschema:"connect timeout and maximum inactivity during the transfer, in seconds (default 30)"`
	AllowPrivate   bool    `json:"allow_private,omitempty" jsonschema:"permit loopback/private/link-local targets (subject to server policy)"`
}

// localSource is an opened upload source.
type localSource struct {
	f    *os.File
	info os.FileInfo
	name string
	path string
}

func openSource(d *tools.Deps, p string) (*localSource, error) {
	if strings.TrimSpace(p) == "" {
		return nil, fmt.Errorf("file is required: the path of a file inside an allowed read directory (see netkit_info)")
	}
	f, st, err := d.Files.OpenRead(p, d.Cfg.UploadBytes(0))
	if err != nil {
		return nil, err
	}
	return &localSource{f: f, info: st, name: st.Name(), path: f.Name()}, nil
}

func (s *localSource) Close() error { return s.f.Close() }

// fileInfo builds the transfer file description for an upload.
func (s *localSource) fileInfo(sha string, contentType string) types.FileInfo {
	if contentType == "" {
		contentType = fileio.DetectContentType(s.name, nil)
	}
	return types.FileInfo{Name: s.name, Path: s.path, SizeBytes: s.info.Size(), SHA256: sha, ContentType: contentType}
}

// remoteTarget resolves the remote path of an upload: a trailing slash (or
// an empty path) means "into this directory, keeping the local name".
func remoteTarget(remote, localName string) string {
	if remote == "" {
		return localName
	}
	if strings.HasSuffix(remote, "/") {
		return remote + localName
	}
	return remote
}

func newResult() *types.TransferResult {
	return &types.TransferResult{Meta: map[string]any{}}
}

func finish(r *types.TransferResult, start time.Time) *types.TransferResult {
	r.TimingMS.Total = types.MS(time.Since(start))
	if len(r.Meta) == 0 {
		r.Meta = nil
	}
	return r
}

// progressReader reports bytes read against total.
type progressReader struct {
	r     io.Reader
	n     int64
	base  int64
	total int64
	fn    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if n > 0 && p.fn != nil {
		p.fn(p.base+p.n, p.total)
	}
	return n, err
}

// partialLocal returns the size of an existing partial download at p (or
// -1 when it does not exist / is not readable).
func partialLocal(d *tools.Deps, p string) int64 {
	real, err := d.Files.ResolveRead(p)
	if err != nil {
		return -1
	}
	st, err := os.Stat(real)
	if err != nil {
		return -1
	}
	return st.Size()
}

// preparePartial copies the first n bytes of the existing file at p into w
// (so the final file hash covers the whole file).
func preparePartial(d *tools.Deps, p string, w io.Writer, n int64) error {
	f, _, err := d.Files.OpenRead(p, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(w, f, n); err != nil {
		return fmt.Errorf("reading the partial local file: %w", err)
	}
	return nil
}

// ctxErr turns a cancelled/timeout context into an actionable message.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("transfer cancelled: %w", err)
	}
	return err
}
