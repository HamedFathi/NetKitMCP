package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// hawkSigner implements Hawk HTTP authentication (header scheme).
type hawkSigner struct {
	cfg *HawkConfig
	h   func() hash.Hash
}

func newHawkSigner(cfg *HawkConfig) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth hawk: the hawk object is required")
	}
	if cfg.ID == "" || cfg.Key == "" {
		return nil, fmt.Errorf("auth hawk: id and key are required")
	}
	s := &hawkSigner{cfg: cfg}
	switch strings.ToLower(cfg.Algorithm) {
	case "", "sha256":
		s.h = sha256.New
	case "sha1":
		s.h = sha1.New
	default:
		return nil, fmt.Errorf("auth hawk: algorithm must be sha256 or sha1")
	}
	return s, nil
}

// HawkArtifacts are the inputs of a Hawk MAC.
type HawkArtifacts struct {
	TS       int64
	Nonce    string
	Method   string
	Resource string
	Host     string
	Port     string
	Hash     string
	Ext      string
	App      string
	Dlg      string
}

// HawkNormalized returns the normalized header string ("hawk.1.header").
func HawkNormalized(a HawkArtifacts) string {
	var b strings.Builder
	b.WriteString("hawk.1.header\n")
	b.WriteString(strconv.FormatInt(a.TS, 10) + "\n")
	b.WriteString(a.Nonce + "\n")
	b.WriteString(strings.ToUpper(a.Method) + "\n")
	b.WriteString(a.Resource + "\n")
	b.WriteString(strings.ToLower(a.Host) + "\n")
	b.WriteString(a.Port + "\n")
	b.WriteString(a.Hash + "\n")
	b.WriteString(strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(a.Ext) + "\n")
	if a.App != "" {
		b.WriteString(a.App + "\n")
		b.WriteString(a.Dlg + "\n")
	}
	return b.String()
}

// HawkMAC computes the request MAC.
func HawkMAC(h func() hash.Hash, key string, a HawkArtifacts) string {
	m := hmac.New(h, []byte(key))
	m.Write([]byte(HawkNormalized(a)))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// HawkPayloadHash computes the payload hash for a content type and body.
func HawkPayloadHash(h func() hash.Hash, contentType string, body []byte) string {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	d := h()
	d.Write([]byte("hawk.1.payload\n" + ct + "\n"))
	d.Write(body)
	d.Write([]byte("\n"))
	return base64.StdEncoding.EncodeToString(d.Sum(nil))
}

// Sign implements Signer.
func (s *hawkSigner) Sign(_ context.Context, req *http.Request) error {
	c := s.cfg
	a := HawkArtifacts{
		TS:       c.Timestamp,
		Nonce:    c.Nonce,
		Method:   req.Method,
		Resource: req.URL.RequestURI(),
		Host:     req.URL.Hostname(),
		Port:     req.URL.Port(),
		Ext:      c.Ext,
		App:      c.App,
		Dlg:      c.Dlg,
	}
	if req.Host != "" {
		if h, p, err := net.SplitHostPort(req.Host); err == nil {
			a.Host, a.Port = h, p
		} else {
			a.Host = strings.Trim(req.Host, "[]")
		}
	}
	if a.Port == "" {
		a.Port = "80"
		if strings.EqualFold(req.URL.Scheme, "https") || strings.EqualFold(req.URL.Scheme, "wss") {
			a.Port = "443"
		}
	}
	if a.TS == 0 {
		a.TS = now().Unix()
	}
	if a.Nonce == "" {
		a.Nonce = randomString(6)
	}
	if c.Payload {
		body, err := readBody(req)
		if err != nil {
			return err
		}
		a.Hash = HawkPayloadHash(s.h, req.Header.Get("Content-Type"), body)
	}
	mac := HawkMAC(s.h, c.Key, a)
	esc := func(v string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) }
	parts := []string{
		`id="` + esc(c.ID) + `"`,
		`ts="` + strconv.FormatInt(a.TS, 10) + `"`,
		`nonce="` + esc(a.Nonce) + `"`,
	}
	if a.Hash != "" {
		parts = append(parts, `hash="`+a.Hash+`"`)
	}
	if a.Ext != "" {
		parts = append(parts, `ext="`+esc(a.Ext)+`"`)
	}
	parts = append(parts, `mac="`+mac+`"`)
	if a.App != "" {
		parts = append(parts, `app="`+esc(a.App)+`"`)
		if a.Dlg != "" {
			parts = append(parts, `dlg="`+esc(a.Dlg)+`"`)
		}
	}
	req.Header.Set("Authorization", "Hawk "+strings.Join(parts, ", "))
	return nil
}
