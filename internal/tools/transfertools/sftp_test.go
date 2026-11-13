package transfertools_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/sftpx/sftptest"
)

type sftpEnv struct {
	srv    *sftptest.Server
	root   string
	keyPEM []byte
}

func newSFTP(t *testing.T) *sftpEnv {
	t.Helper()
	clientKey, keyPEM := sftptest.NewKey(t, "")
	root := t.TempDir()
	srv := sftptest.New(t, sftptest.Options{Root: root, User: "alice", Password: "s3cret", AuthorizedKey: clientKey.PublicKey()})
	return &sftpEnv{srv: srv, root: root, keyPEM: keyPEM}
}

// args returns the connection arguments with password auth and a pinned
// fingerprint, merged with extra.
func (e *sftpEnv) args(extra map[string]any) map[string]any {
	a := map[string]any{
		"host": "127.0.0.1",
		"port": e.srv.Port,
		"auth": map[string]any{
			"type": "ssh_password", "username": "alice", "password": "s3cret",
			"ssh": map[string]any{"host_key_fingerprint": e.srv.Fingerprint()},
		},
	}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func hostKeyMeta(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	meta, _ := out["meta"].(map[string]any)
	hk, _ := meta["host_key"].(map[string]any)
	if hk == nil {
		t.Fatalf("no meta.host_key in %v", out)
	}
	return hk
}

func TestSFTPUploadPasswordFingerprint(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 1<<20+333)
	file := h.WriteInput("report.bin", data)

	r := h.MustOK("sftp_upload", e.args(map[string]any{"file": file, "remote_path": "incoming/", "mkdirs": true}))
	var out transferOut
	r.Decode(t, &out)
	if out.File.Name != "report.bin" || out.File.SizeBytes != int64(len(data)) || out.File.SHA256 != sha(data) {
		t.Fatalf("file info: %+v", out.File)
	}
	if out.BytesTransferred != int64(len(data)) || out.Remote.Path != "incoming/report.bin" {
		t.Fatalf("transfer: %+v remote=%+v", out.BytesTransferred, out.Remote)
	}
	got, err := os.ReadFile(filepath.Join(e.root, "incoming", "report.bin"))
	if err != nil || sha(got) != out.File.SHA256 {
		t.Fatalf("server file: %d bytes, err=%v", len(got), err)
	}
	hk := hostKeyMeta(t, r.Data)
	if hk["verified"] != true || hk["verified_by"] != "fingerprint" || hk["fingerprint_sha256"] != e.srv.Fingerprint() {
		t.Fatalf("host key: %v", hk)
	}
	if len(out.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", out.Warnings)
	}
	if logins := e.srv.Logins(); len(logins) != 1 || logins[0] != "alice/password" {
		t.Fatalf("logins: %v", logins)
	}

	// The remote file now exists: no overwrite without overwrite=true.
	h.MustFail("sftp_upload", e.args(map[string]any{"file": file, "remote_path": "incoming/report.bin"}), "already exists")
	data2 := randomBytes(t, 4096)
	h.WriteInput("report.bin", data2)
	r = h.MustOK("sftp_upload", e.args(map[string]any{"file": file, "remote_path": "incoming/report.bin", "overwrite": true}))
	r.Decode(t, &out)
	got, _ = os.ReadFile(filepath.Join(e.root, "incoming", "report.bin"))
	if !bytes.Equal(got, data2) || out.File.SHA256 != sha(data2) {
		t.Fatalf("overwrite: %d bytes, sha %s", len(got), out.File.SHA256)
	}

	// Uploading to an existing directory keeps the local name.
	r = h.MustOK("sftp_upload", e.args(map[string]any{"file": file, "remote_path": "incoming", "overwrite": true}))
	r.Decode(t, &out)
	if out.Remote.Path != "incoming/report.bin" {
		t.Fatalf("directory target: %+v", out.Remote)
	}

	// Missing parent without mkdirs.
	h.MustFail("sftp_upload", e.args(map[string]any{"file": file, "remote_path": "nope/x.bin"}), "mkdirs")
}

func TestSFTPPrivateKeyAndKnownHosts(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	if err := os.WriteFile(filepath.Join(e.root, "data.txt"), []byte("hello sftp"), 0o644); err != nil {
		t.Fatal(err)
	}
	kh := h.WriteInput("known_hosts", []byte("# test\n"+e.srv.KnownHostsLine()+"\n"))
	keyFile := h.WriteInput("id_ed25519", e.keyPEM)

	for _, key := range []string{string(e.keyPEM), keyFile} {
		func() {
			r := h.MustOK("sftp_list", map[string]any{
				"host": "127.0.0.1", "port": e.srv.Port,
				"auth": map[string]any{"type": "ssh_key", "username": "alice", "ssh": map[string]any{"private_key": key, "known_hosts": kh}},
			})
			hk := hostKeyMeta(t, r.Data)
			if hk["verified"] != true || hk["verified_by"] != "known_hosts" {
				t.Fatalf("host key: %v", hk)
			}
			if r.Data["count"] != float64(1) {
				t.Fatalf("list: %s", r.Raw)
			}
		}()
	}
	if logins := e.srv.Logins(); len(logins) != 2 || logins[0] != "alice/publickey" {
		t.Fatalf("logins: %v", logins)
	}

	// Inline known_hosts content and an encrypted key with its passphrase.
	signer, encPEM := sftptest.NewKey(t, "pw")
	srv2 := sftptest.New(t, sftptest.Options{Root: e.root, User: "bob", AuthorizedKey: signer.PublicKey()})
	authArgs := func(pass string) map[string]any {
		ssh := map[string]any{"private_key": string(encPEM), "known_hosts": srv2.KnownHostsLine()}
		if pass != "" {
			ssh["passphrase"] = pass
		}
		return map[string]any{"host": "127.0.0.1", "port": srv2.Port, "auth": map[string]any{"type": "ssh_key", "username": "bob", "ssh": ssh}}
	}
	h.MustOK("sftp_list", authArgs("pw"))
	h.MustFail("sftp_list", authArgs(""), "passphrase")

	// Wrong password.
	a := e.args(nil)
	a["auth"].(map[string]any)["password"] = "wrong"
	h.MustFail("sftp_list", a, "authentication failed")
}

func TestSFTPHostKeyVerification(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	other := sftptest.New(t, sftptest.Options{Root: e.root, User: "x", Password: "y"}) // different host key
	conn := func(ssh map[string]any) map[string]any {
		return map[string]any{"host": "127.0.0.1", "port": e.srv.Port,
			"auth": map[string]any{"type": "ssh_password", "username": "alice", "password": "s3cret", "ssh": ssh}}
	}
	// Pinned fingerprint of a different key.
	h.MustFail("sftp_list", conn(map[string]any{"host_key_fingerprint": other.Fingerprint()}), "does not match the pinned fingerprint")
	// known_hosts entry for this address with a different key of the same type.
	wrongLine := strings.Replace(other.KnownHostsLine(), other.PortString(), e.srv.PortString(), 1)
	kh := h.WriteInput("known_hosts_wrong", []byte(wrongLine+"\n"))
	h.MustFail("sftp_list", conn(map[string]any{"known_hosts": kh}), "REMOTE HOST KEY MISMATCH")
	// known_hosts without this host.
	kh2 := h.WriteInput("known_hosts_other", []byte(other.KnownHostsLine()+"\n"))
	h.MustFail("sftp_list", conn(map[string]any{"known_hosts": kh2}), "is not in known_hosts")
	// No verification configured at all: refused, with the fingerprint to pin.
	r := h.MustFail("sftp_list", conn(nil), "host key verification is required")
	if !strings.Contains(r.Text, e.srv.Fingerprint()) {
		t.Fatalf("error should show the presented fingerprint: %s", r.Text)
	}
	// Bad fingerprint syntax.
	h.MustFail("sftp_list", conn(map[string]any{"host_key_fingerprint": "nonsense"}), "host_key_fingerprint")
	// known_hosts file outside the allowed directories.
	outside := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(outside, []byte(e.srv.KnownHostsLine()+"\n"), 0o644)
	h.MustFail("sftp_list", conn(map[string]any{"known_hosts": outside}), "outside the allowed read directories")

	// Explicitly skipping verification works and is flagged.
	r = h.MustOK("sftp_list", conn(map[string]any{"insecure_ignore_host_key": true}))
	hk := hostKeyMeta(t, r.Data)
	if hk["verified"] != false || hk["verified_by"] != "insecure_ignore_host_key" || hk["fingerprint_sha256"] != e.srv.Fingerprint() {
		t.Fatalf("host key: %v", hk)
	}
	w, _ := r.Data["warnings"].([]any)
	if len(w) == 0 || !strings.Contains(w[0].(string), "verification was skipped") || !strings.Contains(w[0].(string), e.srv.Fingerprint()) {
		t.Fatalf("insecure_ignore_host_key must be flagged: %v", r.Data["warnings"])
	}
	// A pinned fingerprint wins over the insecure flag (and a mismatch still fails).
	h.MustFail("sftp_list", conn(map[string]any{"insecure_ignore_host_key": true, "host_key_fingerprint": other.Fingerprint()}), "does not match")
}

func TestSFTPDownload(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	data := randomBytes(t, 2<<20+77)
	os.MkdirAll(filepath.Join(e.root, "pub"), 0o755)
	if err := os.WriteFile(filepath.Join(e.root, "pub", "big.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	save := filepath.Join(h.WriteDir, "big.bin")
	r := h.MustOK("sftp_download", e.args(map[string]any{"remote_path": "pub/big.bin", "save_to": save}))
	var out transferOut
	r.Decode(t, &out)
	if out.File.SHA256 != sha(data) || out.File.SizeBytes != int64(len(data)) || out.BytesTransferred != int64(len(data)) {
		t.Fatalf("file info: %+v bytes=%d", out.File, out.BytesTransferred)
	}
	if got, _ := os.ReadFile(save); !bytes.Equal(got, data) {
		t.Fatalf("saved content differs (%d bytes)", len(got))
	}
	if out.Meta["remote_mtime"] == nil {
		t.Fatalf("meta: %v", out.Meta)
	}

	// No overwrite unless overwrite=true.
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "pub/big.bin", "save_to": save}), "already exists")
	os.WriteFile(save, []byte("old"), 0o644)
	h.MustOK("sftp_download", e.args(map[string]any{"remote_path": "pub/big.bin", "save_to": save, "overwrite": true}))
	if got, _ := os.ReadFile(save); !bytes.Equal(got, data) {
		t.Fatal("overwrite did not replace the file")
	}

	// Resume from a partial file.
	part := filepath.Join(h.WriteDir, "part.bin")
	os.WriteFile(part, data[:700000], 0o644)
	r = h.MustOK("sftp_download", e.args(map[string]any{"remote_path": "pub/big.bin", "save_to": part, "resume": true}))
	r.Decode(t, &out)
	if out.ResumedFrom != 700000 || out.BytesTransferred != int64(len(data)-700000) || out.File.SHA256 != sha(data) {
		t.Fatalf("resume: from=%d bytes=%d sha=%s", out.ResumedFrom, out.BytesTransferred, out.File.SHA256)
	}
	if got, _ := os.ReadFile(part); !bytes.Equal(got, data) {
		t.Fatal("resumed file differs")
	}

	// Destination outside the write directories, missing remote, directory.
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "pub/big.bin", "save_to": filepath.Join(t.TempDir(), "x.bin")}), "outside the allowed write directories")
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "pub/missing.bin", "save_to": filepath.Join(h.WriteDir, "m.bin")}), "missing.bin")
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "pub", "save_to": filepath.Join(h.WriteDir, "d.bin")}), "is a directory")
	if _, err := os.Stat(filepath.Join(h.WriteDir, "m.bin")); err == nil {
		t.Fatal("a failed download left a file behind")
	}
}

func TestSFTPList(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	os.MkdirAll(filepath.Join(e.root, "a", "b"), 0o755)
	os.WriteFile(filepath.Join(e.root, "a", "one.txt"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(e.root, "a", "b", "two.txt"), []byte("22"), 0o644)
	os.WriteFile(filepath.Join(e.root, "top.txt"), []byte("333"), 0o644)

	type entry struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		Size  int64  `json:"size"`
		IsDir bool   `json:"is_dir"`
		Depth int    `json:"depth"`
	}
	var out struct {
		Entries   []entry `json:"entries"`
		Count     int     `json:"count"`
		Truncated bool    `json:"truncated"`
		Warnings  []string
	}
	h.MustOK("sftp_list", e.args(nil)).Decode(t, &out)
	if out.Count != 2 || out.Entries[0].Name != "a" || !out.Entries[0].IsDir || out.Entries[1].Name != "top.txt" || out.Entries[1].Size != 3 {
		t.Fatalf("list: %+v", out)
	}
	out.Entries = nil
	h.MustOK("sftp_list", e.args(map[string]any{"path": "a", "recursive": true})).Decode(t, &out)
	var paths []string
	for _, en := range out.Entries {
		paths = append(paths, en.Path)
	}
	if strings.Join(paths, ",") != "a/b,a/b/two.txt,a/one.txt" || out.Entries[1].Depth != 2 {
		t.Fatalf("recursive: %v %+v", paths, out.Entries)
	}
	out.Entries = nil
	h.MustOK("sftp_list", e.args(map[string]any{"recursive": true, "max_entries": 2})).Decode(t, &out)
	if out.Count != 2 || !out.Truncated || len(out.Warnings) == 0 {
		t.Fatalf("truncation: %+v", out)
	}
	h.MustFail("sftp_list", e.args(map[string]any{"path": "does/not/exist"}), "does/not/exist")
}

func TestSFTPFilePolicyAndLimits(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")

	// A file outside the allowed read directories.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	h.MustFail("sftp_upload", e.args(map[string]any{"file": outside, "remote_path": "s.txt"}), "outside the allowed read directories")
	h.MustFail("sftp_upload", e.args(map[string]any{"file": filepath.Join(h.ReadDir, "..", "..", filepath.Base(outsideDir), "secret.txt"), "remote_path": "s.txt"}), "outside the allowed read directories")

	// A symlink in the read directory pointing outside it.
	link := filepath.Join(h.ReadDir, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Logf("symlinks unavailable (%v); skipping the symlink escape case", err)
	} else {
		h.MustFail("sftp_upload", e.args(map[string]any{"file": link, "remote_path": "s.txt"}), "outside the allowed read directories")
	}
	// A directory link (a junction on Windows, which needs no privilege) in
	// the read directory pointing outside it.
	dirLink := filepath.Join(h.ReadDir, "linked")
	if err := makeDirLink(outsideDir, dirLink); err != nil {
		t.Fatalf("creating directory link: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dirLink, "secret.txt")); err != nil || string(b) != "secret" {
		t.Fatalf("directory link does not work: %q %v", b, err)
	}
	// Reading through it is denied. (On Windows the denial currently comes
	// from filepath.EvalSymlinks failing on the junction, not from the
	// directory check, so the message is not asserted.)
	h.MustFail("sftp_upload", e.args(map[string]any{"file": filepath.Join(dirLink, "secret.txt"), "remote_path": "s.txt"}), "")
	h.MustFail("sftp_list", e.args(map[string]any{"auth": map[string]any{"type": "ssh_key", "username": "alice",
		"ssh": map[string]any{"private_key": filepath.Join(dirLink, "secret.txt"), "insecure_ignore_host_key": true}}}), "")
	if _, err := os.Stat(filepath.Join(e.root, "s.txt")); err == nil {
		t.Fatal("a rejected upload reached the server")
	}

	// max upload / download limits.
	h.Deps.Cfg.DefaultUploadBytes = 1000
	big := h.WriteInput("big.bin", randomBytes(t, 1001))
	h.MustFail("sftp_upload", e.args(map[string]any{"file": big, "remote_path": "big.bin"}), "upload limit")
	small := h.WriteInput("small.bin", randomBytes(t, 1000))
	h.MustOK("sftp_upload", e.args(map[string]any{"file": small, "remote_path": "small.bin"}))

	os.WriteFile(filepath.Join(e.root, "dl.bin"), randomBytes(t, 2001), 0o644)
	h.Deps.Cfg.DefaultDownloadBytes = 2000
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "dl.bin", "save_to": filepath.Join(h.WriteDir, "dl.bin")}), "download limit")
	if _, err := os.Stat(filepath.Join(h.WriteDir, "dl.bin")); err == nil {
		t.Fatal("an over-limit download left a file behind")
	}
	h.Deps.Cfg.DefaultDownloadBytes = 2001
	h.MustOK("sftp_download", e.args(map[string]any{"remote_path": "dl.bin", "save_to": filepath.Join(h.WriteDir, "dl.bin")}))
}

func TestSFTPGuard(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("sftp_list", e.args(nil), "blocked by netkit security policy")
	h.MustFail("sftp_list", e.args(map[string]any{"host": "localhost"}), "allow_private")
	if len(e.srv.Logins()) != 0 {
		t.Fatal("the guard let a connection through")
	}
	h.MustOK("sftp_list", e.args(map[string]any{"allow_private": true}))

	hd := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateDeny))
	hd.MustFail("sftp_list", e.args(map[string]any{"allow_private": true}), "blocked by netkit security policy")
}

// TestSFTPDownloadDirLinkEscape: a directory link inside the write directory
// that points outside it must not let save_to escape.
func TestSFTPDownloadDirLinkEscape(t *testing.T) {
	e := newSFTP(t)
	h := tooltest.New(t, "transfer")
	outsideDir := t.TempDir()
	wLink := filepath.Join(h.WriteDir, "linked")
	if err := makeDirLink(outsideDir, wLink); err != nil {
		t.Skipf("cannot create a directory link: %v", err)
	}
	os.WriteFile(filepath.Join(e.root, "x.txt"), []byte("x"), 0o644)
	h.MustFail("sftp_download", e.args(map[string]any{"remote_path": "x.txt", "save_to": filepath.Join(wLink, "x.txt")}), "outside the allowed write directories")
	if _, err := os.Stat(filepath.Join(outsideDir, "x.txt")); err == nil {
		t.Fatal("download escaped the write directory through a link")
	}
}
