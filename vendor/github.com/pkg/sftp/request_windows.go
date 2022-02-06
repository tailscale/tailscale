package sftp

import (
	"path"
	"path/filepath"
	"syscall"
)

func fakeFileInfoSys() interface{} {
	return syscall.Win32FileAttributeData{}
}

func testOsSys(sys interface{}) error {
	return nil
}

func toLocalPath(p string) string {
	lp := filepath.FromSlash(p)

	if path.IsAbs(p) {
		tmp := lp
		for len(tmp) > 0 && tmp[0] == '\\' {
			tmp = tmp[1:]
		}

		if filepath.IsAbs(tmp) {
			// If the FromSlash without any starting slashes is absolute,
			// then we have a filepath encoded with a prefix '/'.
			// e.g. "/C:/Windows" to "C:\\Windows"
			return tmp
		}

		tmp += "\\"

		if filepath.IsAbs(tmp) {
			// If the FromSlash without any starting slashes but with extra end slash is absolute,
			// then we have a filepath encoded with a prefix '/' and a dropped '/' at the end.
			// e.g. "/C:" to "C:\\"
			return tmp
		}
	}

	return lp
}
