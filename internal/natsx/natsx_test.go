package natsx

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestNormalizeServers(t *testing.T) {
	got, err := NormalizeServers(" host1, nats://h2:1234 ,tls://h3, ws://h4:8080/x,,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nats://host1:4222", "nats://h2:1234", "tls://h3:4222", "ws://h4:8080/x"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"", " , ", "http://h", "nats://:4222"} {
		if _, err := NormalizeServers(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestValidateSubject(t *testing.T) {
	for _, s := range []string{"a", "a.b.c", "_INBOX.x"} {
		if err := ValidateSubject(s, false); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"a.*", "a.>", "*.b.>"} {
		if err := ValidateSubject(s, true); err != nil {
			t.Errorf("%q (wildcards): %v", s, err)
		}
		if err := ValidateSubject(s, false); err == nil {
			t.Errorf("%q: wildcard accepted for publish", s)
		}
	}
	for _, s := range []string{"", "a b", "a..b", ".a", "a.", "a.>.b", "a.b*", "a.>x"} {
		if err := ValidateSubject(s, true); err == nil {
			t.Errorf("%q: expected an error", s)
		}
	}
}

func TestHeaders(t *testing.T) {
	if Headers(nil) != nil || FlattenHeaders(nil) != nil {
		t.Fatal("empty headers must be nil")
	}
	h := Headers(map[string]string{"A": "1"})
	h.Add("A", "2")
	h.Set("B", "x")
	got := FlattenHeaders(h)
	if got["A"] != "1, 2" || got["B"] != "x" || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestParseCreds(t *testing.T) {
	akp, _ := nkeys.CreateAccount()
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	claims := jwt.NewUserClaims(upub)
	token, err := claims.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := ukp.Seed()
	creds := fmt.Sprintf("-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n"+
		"-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------\n", token, seed)
	gotJWT, gotSeed, err := ParseCreds([]byte(creds))
	if err != nil {
		t.Fatal(err)
	}
	if gotJWT != token || gotSeed != string(seed) {
		t.Fatalf("got %q / %q", gotJWT, gotSeed)
	}
	if _, _, err := ParseCreds([]byte("garbage")); err == nil {
		t.Fatal("expected an error for garbage creds")
	}
}
