package stompx

import (
	"testing"

	"github.com/go-stomp/stomp/v3"
)

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in       string
		forceTLS bool
		want     Target
	}{
		{"h:1", false, Target{HostPort: "h:1", Host: "h"}},
		{"h", false, Target{HostPort: "h:61613", Host: "h"}},
		{"h", true, Target{HostPort: "h:61614", Host: "h", TLS: true}},
		{"stomp://h:2", false, Target{HostPort: "h:2", Host: "h"}},
		{"stomp+ssl://h", false, Target{HostPort: "h:61614", Host: "h", TLS: true}},
		{"ssl://h:3", false, Target{HostPort: "h:3", Host: "h", TLS: true}},
		{"[::1]:4", false, Target{HostPort: "[::1]:4", Host: "::1"}},
	}
	for _, c := range cases {
		got, err := ParseAddress(c.in, c.forceTLS)
		if err != nil || got != c.want {
			t.Errorf("%s: got %+v, %v", c.in, got, err)
		}
	}
	for _, bad := range []string{"", "http://h", "stomp://:1"} {
		if _, err := ParseAddress(bad, false); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestAckMode(t *testing.T) {
	for in, want := range map[string]stomp.AckMode{"": stomp.AckAuto, "auto": stomp.AckAuto, "Client": stomp.AckClient, "client_individual": stomp.AckClientIndividual} {
		got, err := AckMode(in)
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v", in, got, err)
		}
	}
	if _, err := AckMode("maybe"); err == nil {
		t.Error("expected an error")
	}
}
