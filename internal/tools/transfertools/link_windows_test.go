package transfertools_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// makeDirLink creates a directory junction at link pointing to target.
// Junctions (unlike symlinks) need no special privilege on Windows.
func makeDirLink(target, link string) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if tp, err := windows.UTF16PtrFromString(target); err == nil {
		buf := make([]uint16, windows.MAX_LONG_PATH)
		if n, err := windows.GetLongPathName(tp, &buf[0], uint32(len(buf))); err == nil && n > 0 && int(n) < len(buf) {
			target = windows.UTF16ToString(buf[:n])
		}
	}
	if err := os.Mkdir(link, 0o755); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	sub := utf16.Encode([]rune(`\??\` + target))
	prn := utf16.Encode([]rune(target))
	subLen, prnLen := len(sub)*2, len(prn)*2
	// PathBuffer: substitute name + NUL, print name + NUL.
	pathBuf := make([]byte, subLen+2+prnLen+2)
	for i, c := range sub {
		binary.LittleEndian.PutUint16(pathBuf[i*2:], c)
	}
	for i, c := range prn {
		binary.LittleEndian.PutUint16(pathBuf[subLen+2+i*2:], c)
	}
	buf := make([]byte, 8+8+len(pathBuf))
	binary.LittleEndian.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], uint16(8+len(pathBuf)))
	binary.LittleEndian.PutUint16(buf[8:], 0)                 // SubstituteNameOffset
	binary.LittleEndian.PutUint16(buf[10:], uint16(subLen))   // SubstituteNameLength
	binary.LittleEndian.PutUint16(buf[12:], uint16(subLen+2)) // PrintNameOffset
	binary.LittleEndian.PutUint16(buf[14:], uint16(prnLen))   // PrintNameLength
	copy(buf[16:], pathBuf)
	var n uint32
	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
}
