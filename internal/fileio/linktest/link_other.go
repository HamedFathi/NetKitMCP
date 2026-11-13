//go:build !windows

package linktest

import "os"

func dirLink(target, link string) error { return os.Symlink(target, link) }
