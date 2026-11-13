//go:build !windows

package transfertools_test

import "os"

// makeDirLink creates a directory symlink at link pointing to target.
func makeDirLink(target, link string) error { return os.Symlink(target, link) }
