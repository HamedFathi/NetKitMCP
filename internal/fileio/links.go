package fileio

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveLinks returns the absolute, link-free form of an existing path.
//
// On Windows, filepath.EvalSymlinks does not evaluate directory junctions
// (mount points) since Go 1.23, so a junction inside an allowed directory
// that points elsewhere would pass the directory check. There the path is
// walked component by component and every symlink or junction is resolved
// with os.Readlink; the link-free result is then normalised (case, 8.3
// short names) with EvalSymlinks so it compares equal to the allowed dirs.
func resolveLinks(p string) (string, error) {
	if runtime.GOOS != "windows" {
		return filepath.EvalSymlinks(p)
	}
	r, err := resolveWindows(p, 0)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(r)
}

func resolveWindows(p string, depth int) (string, error) {
	if depth > 40 {
		return "", fmt.Errorf("resolve %q: too many levels of links", p)
	}
	p = filepath.Clean(p)
	vol := filepath.VolumeName(p)
	cur := vol + string(filepath.Separator)
	rest := strings.TrimLeft(p[len(vol):], `\/`)
	if rest == "" {
		return cur, nil
	}
	parts := strings.Split(rest, string(filepath.Separator))
	for i, part := range parts {
		next := filepath.Join(cur, part)
		st, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if isLink(st) {
			if target, err := os.Readlink(next); err == nil {
				if !filepath.IsAbs(target) {
					target = filepath.Join(cur, target)
				}
				return resolveWindows(filepath.Join(append([]string{target}, parts[i+1:]...)...), depth+1)
			}
			// Other reparse points (e.g. cloud placeholder files) are not links.
		}
		cur = next
	}
	return cur, nil
}

// isLink reports whether st (from Lstat) may be a symlink or, on Windows, a
// junction (reported as ModeIrregular).
func isLink(st os.FileInfo) bool {
	if st.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return runtime.GOOS == "windows" && st.Mode()&os.ModeIrregular != 0
}
