// Package linktest creates directory links for tests of the file policy.
// On Windows it creates a directory junction (mount point), which needs no
// special privilege, unlike a symlink. Elsewhere it creates a symlink.
package linktest

import "path/filepath"

// DirLink makes link a directory link pointing at target (an existing
// directory).
func DirLink(target, link string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	return dirLink(abs, link)
}
