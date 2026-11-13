package tools_test

import (
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

func TestNetkitInfo(t *testing.T) {
	h := tooltest.New(t, "all")
	r := h.MustOK("netkit_info", map[string]any{})
	if r.Data["version"] == "" {
		t.Fatalf("missing version: %s", r.Text)
	}
	dirs := r.Data["allowed_write_dirs"].([]any)
	if len(dirs) != 1 {
		t.Fatalf("write dirs: %v", dirs)
	}
}
