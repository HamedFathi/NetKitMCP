package transfertools_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/ftpx/ftptest"
)

func ftpArgs(s *ftptest.Server, extra map[string]any) map[string]any {
	a := map[string]any{
		"host": "127.0.0.1",
		"port": s.Port,
		"auth": map[string]any{"type": "basic", "username": "bob", "password": "pw"},
	}
	for k, v := range extra {
		if v == nil {
			delete(a, k)
			continue
		}
		a[k] = v
	}
	return a
}

func newFTP(t *testing.T, o ftptest.Options) (*ftptest.Server, string) {
	t.Helper()
	root := t.TempDir()
	if o.User == "" {
		o.User, o.Password = "bob", "pw"
	}
	return ftptest.New(t, root, o), root
}

func TestFTPUploadDownload(t *testing.T) {
	for _, mode := range []struct {
		name string
		o    ftptest.Options
		args map[string]any
	}{
		{"epsv-mlsd", ftptest.Options{MLSD: true}, nil},
		{"pasv-list", ftptest.Options{NoEPSV: true}, nil},
		{"disable-epsv", ftptest.Options{MLSD: true}, map[string]any{"disable_epsv": true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			s, root := newFTP(t, mode.o)
			h := tooltest.New(t, "transfer")
			data := randomBytes(t, 1<<20+4321)
			file := h.WriteInput("payload.bin", data)

			up := func(extra map[string]any) map[string]any {
				m := map[string]any{"file": file}
				for k, v := range mode.args {
					m[k] = v
				}
				for k, v := range extra {
					m[k] = v
				}
				return ftpArgs(s, m)
			}
			r := h.MustOK("ftp_upload", up(map[string]any{"remote_path": "/up/deep/", "mkdirs": true}))
			var out transferOut
			r.Decode(t, &out)
			if out.File.SHA256 != sha(data) || out.File.SizeBytes != int64(len(data)) || out.BytesTransferred != int64(len(data)) || out.Remote.Path != "/up/deep/payload.bin" {
				t.Fatalf("upload: %+v remote=%+v", out.File, out.Remote)
			}
			got, err := os.ReadFile(filepath.Join(root, "up", "deep", "payload.bin"))
			if err != nil || sha(got) != sha(data) {
				t.Fatalf("server file: %d bytes %v", len(got), err)
			}
			if out.Meta["tls"] != "none" || out.Meta["data_connections"] != float64(1) {
				t.Fatalf("meta: %v", out.Meta)
			}
			if len(out.Warnings) == 0 || !strings.Contains(out.Warnings[0], "unencrypted") {
				t.Fatalf("plain-FTP credentials should be flagged: %v", out.Warnings)
			}
			wantData := "EPSV"
			if mode.o.NoEPSV || mode.args["disable_epsv"] == true {
				wantData = "PASV"
			}
			if !s.HasCommand(wantData) {
				t.Fatalf("expected %s, got %v", wantData, s.Commands())
			}
			if mode.args["disable_epsv"] == true && s.HasCommand("EPSV") {
				t.Fatal("disable_epsv still sent EPSV")
			}

			// Existing remote file needs overwrite=true; missing dir without mkdirs fails.
			h.MustFail("ftp_upload", up(map[string]any{"remote_path": "/up/deep/payload.bin"}), "already exists")
			h.MustOK("ftp_upload", up(map[string]any{"remote_path": "/up/deep/payload.bin", "overwrite": true}))
			h.MustFail("ftp_upload", up(map[string]any{"remote_path": "/missing/x.bin"}), "mkdirs")

			// Download with save_to; no overwrite by default; sha256 reported.
			save := filepath.Join(h.WriteDir, "dl.bin")
			dl := func(extra map[string]any) map[string]any {
				m := map[string]any{"remote_path": "/up/deep/payload.bin", "save_to": save}
				for k, v := range mode.args {
					m[k] = v
				}
				for k, v := range extra {
					m[k] = v
				}
				return ftpArgs(s, m)
			}
			r = h.MustOK("ftp_download", dl(nil))
			r.Decode(t, &out)
			if out.File.SHA256 != sha(data) || out.File.SizeBytes != int64(len(data)) {
				t.Fatalf("download: %+v", out.File)
			}
			if b, _ := os.ReadFile(save); !bytes.Equal(b, data) {
				t.Fatal("downloaded content differs")
			}
			h.MustFail("ftp_download", dl(nil), "already exists")
			h.MustOK("ftp_download", dl(map[string]any{"overwrite": true}))

			// Resume with REST.
			part := filepath.Join(h.WriteDir, "part.bin")
			os.WriteFile(part, data[:500000], 0o644)
			r = h.MustOK("ftp_download", dl(map[string]any{"save_to": part, "resume": true}))
			r.Decode(t, &out)
			if out.ResumedFrom != 500000 || out.BytesTransferred != int64(len(data)-500000) || out.File.SHA256 != sha(data) || !s.HasCommand("REST 500000") {
				t.Fatalf("resume: from=%d bytes=%d", out.ResumedFrom, out.BytesTransferred)
			}

			h.MustFail("ftp_download", dl(map[string]any{"remote_path": "/nope.bin", "save_to": filepath.Join(h.WriteDir, "nope.bin")}), "nope.bin")
			if _, err := os.Stat(filepath.Join(h.WriteDir, "nope.bin")); err == nil {
				t.Fatal("failed download left a file")
			}
		})
	}
}

func TestFTPList(t *testing.T) {
	type entry struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		Type  string `json:"type"`
		Size  uint64 `json:"size"`
		IsDir bool   `json:"is_dir"`
		Depth int    `json:"depth"`
		MTime string `json:"mtime"`
	}
	var out struct {
		Entries   []entry        `json:"entries"`
		Count     int            `json:"count"`
		Truncated bool           `json:"truncated"`
		Meta      map[string]any `json:"meta"`
		Warnings  []string       `json:"warnings"`
	}
	for _, c := range []struct {
		name, cmd string
		o         ftptest.Options
		fallback  bool
	}{
		{"mlsd", "MLSD", ftptest.Options{MLSD: true}, false},
		{"list", "LIST", ftptest.Options{}, false},
		{"mlsd-broken", "LIST", ftptest.Options{MLSD: true, FailMLSD: true}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, root := newFTP(t, c.o)
			h := tooltest.New(t, "transfer")
			os.MkdirAll(filepath.Join(root, "pub", "sub"), 0o755)
			os.WriteFile(filepath.Join(root, "pub", "a.txt"), []byte("aaaa"), 0o644)
			os.WriteFile(filepath.Join(root, "pub", "sub", "b.txt"), []byte("bb"), 0o644)

			out.Entries, out.Warnings = nil, nil
			h.MustOK("ftp_list", ftpArgs(s, map[string]any{"path": "/pub"})).Decode(t, &out)
			if out.Count != 2 || out.Entries[0].Name != "a.txt" || out.Entries[0].Size != 4 || out.Entries[0].IsDir ||
				out.Entries[1].Name != "sub" || !out.Entries[1].IsDir || out.Entries[0].Path != "/pub/a.txt" || out.Entries[0].MTime == "" {
				t.Fatalf("list: %+v", out)
			}
			if out.Meta["command"] != c.cmd {
				t.Fatalf("command: %v", out.Meta)
			}
			fellBack := false
			for _, w := range out.Warnings {
				fellBack = fellBack || strings.Contains(w, "MLSD failed")
			}
			if fellBack != c.fallback {
				t.Fatalf("fallback warning: %v", out.Warnings)
			}

			out.Entries = nil
			h.MustOK("ftp_list", ftpArgs(s, map[string]any{"path": "/pub", "recursive": true})).Decode(t, &out)
			var paths []string
			for _, e := range out.Entries {
				paths = append(paths, e.Path)
			}
			if strings.Join(paths, ",") != "/pub/a.txt,/pub/sub,/pub/sub/b.txt" || out.Entries[2].Depth != 2 {
				t.Fatalf("recursive: %v", paths)
			}
			out.Entries = nil
			h.MustOK("ftp_list", ftpArgs(s, map[string]any{"path": "/pub", "recursive": true, "max_entries": 1})).Decode(t, &out)
			if out.Count != 1 || !out.Truncated {
				t.Fatalf("truncated: %+v", out)
			}
		})
	}
}

func TestFTPAuthAndOptions(t *testing.T) {
	s, root := newFTP(t, ftptest.Options{})
	h := tooltest.New(t, "transfer")
	h.MustFail("ftp_list", ftpArgs(s, map[string]any{"auth": map[string]any{"type": "basic", "username": "bob", "password": "bad"}}), "login")
	h.MustFail("ftp_list", ftpArgs(s, map[string]any{"auth": map[string]any{"type": "bearer", "token": "x"}}), "not supported")
	h.MustFail("ftp_list", ftpArgs(s, map[string]any{"tls": "sometimes"}), "tls must be")

	// Anonymous login (auth omitted).
	anon := ftptest.New(t, root, ftptest.Options{})
	h.MustOK("ftp_list", ftpArgs(anon, map[string]any{"auth": nil}))
	if !anon.HasCommand("USER anonymous") {
		t.Fatalf("anonymous login: %v", anon.Commands())
	}
	for _, c := range s.Commands() {
		if strings.Contains(c, "bad") {
			t.Fatalf("password recorded in clear: %q", c)
		}
	}

	// Upload limits and file policy.
	h.Deps.Cfg.DefaultUploadBytes = 100
	big := h.WriteInput("big.bin", randomBytes(t, 101))
	h.MustFail("ftp_upload", ftpArgs(s, map[string]any{"file": big, "remote_path": "/big.bin"}), "upload limit")
	outside := filepath.Join(t.TempDir(), "x")
	os.WriteFile(outside, []byte("x"), 0o644)
	h.MustFail("ftp_upload", ftpArgs(s, map[string]any{"file": outside, "remote_path": "/x"}), "outside the allowed read directories")
	os.WriteFile(filepath.Join(root, "dl.bin"), randomBytes(t, 201), 0o644)
	h.Deps.Cfg.DefaultDownloadBytes = 200
	h.MustFail("ftp_download", ftpArgs(s, map[string]any{"remote_path": "/dl.bin", "save_to": filepath.Join(h.WriteDir, "dl.bin")}), "download limit")
	if s.HasCommand("RETR") {
		t.Fatal("an over-limit download was started")
	}
	h.MustFail("ftp_download", ftpArgs(s, map[string]any{"remote_path": "/dl.bin", "save_to": filepath.Join(t.TempDir(), "dl.bin")}), "outside the allowed write directories")
}

func TestFTPExplicitAndImplicitTLS(t *testing.T) {
	tc, caPEM := ftptest.SelfSigned(t)
	data := randomBytes(t, 300000)
	for _, c := range []struct {
		mode string
		o    ftptest.Options
	}{
		{"explicit", ftptest.Options{TLS: tc, RequireTLS: true, MLSD: true}},
		{"implicit", ftptest.Options{TLS: tc, Implicit: true}},
	} {
		t.Run(c.mode, func(t *testing.T) {
			s, root := newFTP(t, c.o)
			h := tooltest.New(t, "transfer")
			file := h.WriteInput("secure.bin", data)
			r := h.MustOK("ftp_upload", ftpArgs(s, map[string]any{"tls": c.mode, "ca_cert": caPEM, "file": file, "remote_path": "/secure.bin"}))
			var out transferOut
			r.Decode(t, &out)
			if out.Meta["tls"] != c.mode || out.File.SHA256 != sha(data) || len(out.Warnings) != 0 {
				t.Fatalf("upload: %+v %v", out.Meta, out.Warnings)
			}
			if got, _ := os.ReadFile(filepath.Join(root, "secure.bin")); !bytes.Equal(got, data) {
				t.Fatal("uploaded content differs")
			}
			if !s.HasCommand("PROT P") || (c.mode == "explicit" && !s.HasCommand("AUTH TLS")) {
				t.Fatalf("commands: %v", s.Commands())
			}
			r = h.MustOK("ftp_download", ftpArgs(s, map[string]any{"tls": c.mode, "ca_cert": caPEM, "remote_path": "/secure.bin", "save_to": filepath.Join(h.WriteDir, "s.bin")}))
			r.Decode(t, &out)
			if out.File.SHA256 != sha(data) {
				t.Fatalf("download: %+v", out.File)
			}
			h.MustOK("ftp_list", ftpArgs(s, map[string]any{"tls": c.mode, "ca_cert": caPEM}))

			// Without the CA the certificate is rejected; insecure_skip_verify works and is flagged.
			h.MustFail("ftp_list", ftpArgs(s, map[string]any{"tls": c.mode}), "certificate")
			r = h.MustOK("ftp_list", ftpArgs(s, map[string]any{"tls": c.mode, "insecure_skip_verify": true}))
			w, _ := r.Data["warnings"].([]any)
			if len(w) == 0 || !strings.Contains(w[0].(string), "insecure_skip_verify") {
				t.Fatalf("insecure_skip_verify must be flagged: %v", r.Data["warnings"])
			}
		})
	}
	// A server that requires TLS refuses a plain login.
	s, _ := newFTP(t, ftptest.Options{TLS: tc, RequireTLS: true})
	h := tooltest.New(t, "transfer")
	h.MustFail("ftp_list", ftpArgs(s, nil), "TLS required")
}

// TestFTPPasvAddress: a PASV reply pointing at another host (private,
// metadata, public) is not followed by default: data goes to the control IP.
// With a loopback control connection the ftp library also replaces any
// non-loopback PASV address with the control IP when trust_pasv_ip=true.
// That a followed PASV address is checked by the guard (allow_private off,
// public control host) is covered in internal/transfer/ftpx
// (TestPasvAddressIsGuarded), since a loopback test server can only be
// reached with allow_private on.
func TestFTPPasvAddress(t *testing.T) {
	for _, trust := range []bool{false, true} {
		for _, ip := range []string{"10.20.30.40", "169.254.169.254", "203.0.113.50"} {
			s, root := newFTP(t, ftptest.Options{NoEPSV: true, PasvIP: ip})
			os.WriteFile(filepath.Join(root, "f.txt"), []byte("data"), 0o644)
			h := tooltest.New(t, "transfer")
			r := h.MustOK("ftp_download", ftpArgs(s, map[string]any{"remote_path": "/f.txt", "save_to": filepath.Join(h.WriteDir, "f.txt"), "trust_pasv_ip": trust}))
			var out transferOut
			r.Decode(t, &out)
			if out.File.SizeBytes != 4 || s.DataConns() != 1 {
				t.Fatalf("PASV %s trust=%v: %+v data=%d", ip, trust, out.File, s.DataConns())
			}
		}
	}
}

func TestFTPGuard(t *testing.T) {
	s, _ := newFTP(t, ftptest.Options{})
	h := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateOptIn))
	h.MustFail("ftp_list", ftpArgs(s, nil), "blocked by netkit security policy")
	h.MustFail("ftp_list", ftpArgs(s, map[string]any{"host": "localhost"}), "allow_private")
	if len(s.Commands()) != 0 {
		t.Fatalf("the guard let a connection through: %v", s.Commands())
	}
	h.MustOK("ftp_list", ftpArgs(s, map[string]any{"allow_private": true}))

	hd := tooltest.New(t, "transfer", tooltest.WithPrivateMode(config.PrivateDeny))
	hd.MustFail("ftp_list", ftpArgs(s, map[string]any{"allow_private": true}), "blocked by netkit security policy")
}

// TestFTPListFallbackReconnectFails: when MLSD fails and the reconnect for
// the LIST fallback is refused, ftp_list must return an error (not panic).
func TestFTPListFallbackReconnectFails(t *testing.T) {
	s, _ := newFTP(t, ftptest.Options{MLSD: true, FailMLSD: true, MaxSessions: 1})
	h := tooltest.New(t, "transfer")
	h.MustFail("ftp_list", ftpArgs(s, nil), "421")
	// The server (and harness) still work afterwards.
	h.MustFail("ftp_list", ftpArgs(s, nil), "421")
}

func TestTransferEmptyFile(t *testing.T) {
	tc, caPEM := ftptest.SelfSigned(t)
	h := tooltest.New(t, "transfer")
	empty := h.WriteInput("empty.txt", nil)
	for _, mode := range []string{"none", "explicit"} {
		s, root := newFTP(t, ftptest.Options{TLS: tc, MLSD: true})
		extra := map[string]any{"tls": mode, "ca_cert": caPEM}
		up := ftpArgs(s, map[string]any{"file": empty, "remote_path": "/empty.txt"})
		dl := ftpArgs(s, map[string]any{"remote_path": "/empty.txt", "save_to": filepath.Join(h.WriteDir, "empty-"+mode+".txt")})
		for k, v := range extra {
			up[k], dl[k] = v, v
		}
		var out transferOut
		h.MustOK("ftp_upload", up).Decode(t, &out)
		if st, err := os.Stat(filepath.Join(root, "empty.txt")); err != nil || st.Size() != 0 || out.File.SHA256 != sha(nil) {
			t.Fatalf("%s upload: %v %+v", mode, err, out.File)
		}
		h.MustOK("ftp_download", dl).Decode(t, &out)
		if out.File.SizeBytes != 0 || out.File.SHA256 != sha(nil) {
			t.Fatalf("%s download: %+v", mode, out.File)
		}
	}

	e := newSFTP(t)
	var out transferOut
	h.MustOK("sftp_upload", e.args(map[string]any{"file": empty, "remote_path": "empty.txt"})).Decode(t, &out)
	if st, err := os.Stat(filepath.Join(e.root, "empty.txt")); err != nil || st.Size() != 0 || out.File.SHA256 != sha(nil) {
		t.Fatalf("sftp upload: %v %+v", err, out.File)
	}
	h.MustOK("sftp_download", e.args(map[string]any{"remote_path": "empty.txt", "save_to": filepath.Join(h.WriteDir, "empty-sftp.txt")})).Decode(t, &out)
	if out.File.SizeBytes != 0 || out.File.SHA256 != sha(nil) {
		t.Fatalf("sftp download: %+v", out.File)
	}
}
