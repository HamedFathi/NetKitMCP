package tools

import "testing"

func TestParseGroups(t *testing.T) {
	g, err := ParseGroups("")
	if err != nil || !g[GroupHTTP] || !g[GroupMQTT] || g[GroupTransfer] {
		t.Fatalf("defaults: %v %v", g, err)
	}
	g, _ = ParseGroups("messaging,lowlevel")
	if !g[GroupMQTT] || !g[GroupMessaging] || !g[GroupLowLevel] || g[GroupHTTP] {
		t.Fatalf("explicit: %v", g)
	}
	g, _ = ParseGroups("all")
	if len(g) != len(AllGroups) {
		t.Fatalf("all: %v", g)
	}
	if _, err := ParseGroups("bogus"); err == nil {
		t.Fatal("unknown group accepted")
	}
}
