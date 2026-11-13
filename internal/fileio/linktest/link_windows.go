//go:build windows

package linktest

import (
	"encoding/binary"
	"os"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// dirLink creates a junction by writing a mount-point reparse buffer:
//
//	ULONG ReparseTag; USHORT ReparseDataLength; USHORT Reserved;
//	USHORT SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength;
//	WCHAR PathBuffer[] (substitute name, NUL, print name, NUL)
func dirLink(target, link string) error {
	if err := os.Mkdir(link, 0o755); err != nil {
		return err
	}
	sub := utf16.Encode([]rune(`\??\` + target))
	prn := utf16.Encode([]rune(target))
	path := make([]uint16, 0, len(sub)+len(prn)+2)
	path = append(append(append(append(path, sub...), 0), prn...), 0)

	buf := make([]byte, 16+2*len(path))
	binary.LittleEndian.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], uint16(8+2*len(path)))
	binary.LittleEndian.PutUint16(buf[8:], 0)
	binary.LittleEndian.PutUint16(buf[10:], uint16(2*len(sub)))
	binary.LittleEndian.PutUint16(buf[12:], uint16(2*(len(sub)+1)))
	binary.LittleEndian.PutUint16(buf[14:], uint16(2*len(prn)))
	for i, c := range path {
		binary.LittleEndian.PutUint16(buf[16+2*i:], c)
	}

	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		os.Remove(link)
		return err
	}
	defer windows.CloseHandle(h)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		os.Remove(link)
		return err
	}
	return nil
}
