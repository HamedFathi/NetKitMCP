package redact

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer abc.def"}, "X-Api-Key": {"k"}, "Accept": {"*/*"}}
	m := Headers(h)
	if m["Authorization"] != "Bearer ***" || m["X-Api-Key"] != "***" || m["Accept"] != "*/*" {
		t.Fatalf("%v", m)
	}
	u := URL("https://user:pw@x.com/p?token=1&q=ok&X-Amz-Signature=abc")
	if strings.Contains(u, "pw") || strings.Contains(u, "token=1") || strings.Contains(u, "abc") || !strings.Contains(u, "q=ok") {
		t.Fatal(u)
	}
	s := Text(`<wsse:Password Type="x">secret</wsse:Password>`)
	if strings.Contains(s, "secret") {
		t.Fatal(s)
	}
}

func TestTextWSSecurityPassword(t *testing.T) {
	masked := map[string]string{
		`<Password>secret</Password>`:                                         `<Password>***</Password>`,
		`<wsse:Password Type="#PasswordText">secret</wsse:Password>`:          `<wsse:Password Type="#PasswordText">***</wsse:Password>`,
		`<wsse-1:Password>secret</wsse-1:Password>`:                           `<wsse-1:Password>***</wsse-1:Password>`,
		`<ns.v2_x:Password>secret</ns.v2_x:Password >`:                        `<ns.v2_x:Password>***</ns.v2_x:Password >`,
		"<o:Password\n  Type=\"x\">multi\nline</o:Password>":                  "<o:Password\n  Type=\"x\">***</o:Password>",
		`<a:Password>one</a:Password><b>keep</b><a:Password>two</a:Password>`: `<a:Password>***</a:Password><b>keep</b><a:Password>***</a:Password>`,
	}
	for in, want := range masked {
		if got := Text(in); got != want {
			t.Errorf("Text(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	unchanged := []string{
		`<PasswordHint>my dog</PasswordHint>`,
		`<ns:PasswordHint Type="x">my dog</ns:PasswordHint>`,
		`<ns:PasswordPolicy><MinLength>8</MinLength></ns:PasswordPolicy>`,
		`<ResetPassword>yes</ResetPassword>`,
		`<Password/>`,
	}
	for _, in := range unchanged {
		if got := Text(in); got != in {
			t.Errorf("Text(%q) changed it to %q", in, got)
		}
	}
	// A hint next to a real password: only the password is masked.
	in := `<PasswordHint>dog</PasswordHint><wsse:Password>secret</wsse:Password>`
	if got := Text(in); got != `<PasswordHint>dog</PasswordHint><wsse:Password>***</wsse:Password>` {
		t.Errorf("got %q", got)
	}
}
