package cpio

import (
	"os"
	"path"
	"time"
)

// headerFileInfo implements os.FileInfo.
type headerFileInfo struct {
	h *Header
}

// Name returns the base name of the file.
func (fi headerFileInfo) Name() string {
	if fi.IsDir() {
		return path.Base(path.Clean(fi.h.Name))
	}
	return path.Base(fi.h.Name)
}

func (fi headerFileInfo) Size() int64        { return fi.h.Size }
func (fi headerFileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time { return fi.h.ModTime }
func (fi headerFileInfo) Sys() interface{}   { return fi.h }

func (fi headerFileInfo) Mode() (mode os.FileMode) {
	// Set file permission bits.
	mode = os.FileMode(fi.h.Mode).Perm()

	// Set setuid, setgid and sticky bits.
	if fi.h.Mode&ModeSetuid != 0 {
		// setuid
		mode |= os.ModeSetuid
	}
	if fi.h.Mode&ModeSetgid != 0 {
		// setgid
		mode |= os.ModeSetgid
	}
	if fi.h.Mode&ModeSticky != 0 {
		// sticky
		mode |= os.ModeSticky
	}

	// Set file mode bits.
	// clear perm, setuid, setgid and sticky bits.
	m := os.FileMode(fi.h.Mode) & 0170000
	if m == ModeDir {
		// directory
		mode |= os.ModeDir
	}
	if m == ModeNamedPipe {
		// named pipe (FIFO)
		mode |= os.ModeNamedPipe
	}
	if m == ModeSymlink {
		// symbolic link
		mode |= os.ModeSymlink
	}
	if m == ModeDevice {
		// device file
		mode |= os.ModeDevice
	}
	if m == ModeCharDevice {
		// Unix character device
		mode |= os.ModeDevice
		mode |= os.ModeCharDevice
	}
	if m == ModeSocket {
		// Unix domain socket
		mode |= os.ModeSocket
	}

	return mode
}
