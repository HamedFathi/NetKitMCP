package transfertools_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type transferOut struct {
	types.TransferResult
}
