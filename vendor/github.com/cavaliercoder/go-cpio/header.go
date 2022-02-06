package cpio

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Mode constants from the cpio spec.
const (
	ModeSetuid     = 04000   // Set uid
	ModeSetgid     = 02000   // Set gid
	ModeSticky     = 01000   // Save text (sticky bit)
	ModeDir        = 040000  // Directory
	ModeNamedPipe  = 010000  // FIFO
	ModeRegular    = 0100000 // Regular file
	ModeSymlink    = 0120000 // Symbolic link
	ModeDevice     = 060000  // Block special file
	ModeCharDevice = 020000  // Character special file
	ModeSocket     = 0140000 // Socket

	ModeType = 0170000 // Mask for the type bits
	ModePerm = 0777    // Unix permission bits
)

const (
	// headerEOF is the value of the filename of the last header in a CPIO archive.
	headerEOF = "TRAILER!!!"
)

var (
	ErrHeader = errors.New("cpio: invalid cpio header")
)

// A FileMode represents a file's mode and permission bits.
type FileMode int64

func (m FileMode) String() string {
	return fmt.Sprintf("%#o", m)
}

// IsDir reports whether m describes a directory. That is, it tests for the
// ModeDir bit being set in m.
func (m FileMode) IsDir() bool {
	return m&ModeDir != 0
}

// IsRegular reports whether m describes a regular file. That is, it tests for
// the ModeRegular bit being set in m.
func (m FileMode) IsRegular() bool {
	return m&^ModePerm == ModeRegular
}

// Perm returns the Unix permission bits in m.
func (m FileMode) Perm() FileMode {
	return m & ModePerm
}

// Checksum is the sum of all bytes	in the file data. This sum is computed
// treating all bytes as unsigned values and using unsigned arithmetic. Only
// the least-significant 32 bits of the sum are stored. Use NewHash to compute
// the actual checksum of an archived file.
type Checksum uint32

func (c Checksum) String() string {
	return fmt.Sprintf("%08X", uint32(c))
}

// A Header represents a single header in a CPIO archive.
type Header struct {
	DeviceID int
	Inode    int64     // inode number
	Mode     FileMode  // permission and mode bits
	UID      int       // user id of the owner
	GID      int       // group id of the owner
	Links    int       // number of inbound links
	ModTime  time.Time // modified time
	Size     int64     // size in bytes
	Name     string    // filename
	Linkname string    // target name of link
	Checksum Checksum  // computed checksum

	pad int64 // bytes to pad before next header
}

// FileInfo returns an os.FileInfo for the Header.
func (h *Header) FileInfo() os.FileInfo {
	return headerFileInfo{h}
}

// FileInfoHeader creates a partially-populated Header from fi.
// If fi describes a symlink, FileInfoHeader records link as the link target.
// If fi describes a directory, a slash is appended to the name.
// Because os.FileInfo's Name method returns only the base name of
// the file it describes, it may be necessary to modify the Name field
// of the returned header to provide the full path name of the file.
func FileInfoHeader(fi os.FileInfo, link string) (*Header, error) {
	if fi == nil {
		return nil, errors.New("cpio: FileInfo is nil")
	}

	if sys, ok := fi.Sys().(*Header); ok {
		// This FileInfo came from a Header (not the OS). Return a copy of the
		// original Header.
		h := &Header{}
		*h = *sys
		return h, nil
	}

	fm := fi.Mode()
	h := &Header{
		Name:    fi.Name(),
		Mode:    FileMode(fi.Mode().Perm()), // or'd with Mode* constants later
		ModTime: fi.ModTime(),
		Size:    fi.Size(),
	}

	switch {
	case fm.IsRegular():
		h.Mode |= ModeRegular
	case fi.IsDir():
		h.Mode |= ModeDir
		h.Name += "/"
		h.Size = 0
	case fm&os.ModeSymlink != 0:
		h.Mode |= ModeSymlink
		h.Linkname = link
	case fm&os.ModeDevice != 0:
		if fm&os.ModeCharDevice != 0 {
			h.Mode |= ModeCharDevice
		} else {
			h.Mode |= ModeDevice
		}
	case fm&os.ModeNamedPipe != 0:
		h.Mode |= ModeNamedPipe
	case fm&os.ModeSocket != 0:
		h.Mode |= ModeSocket
	default:
		return nil, fmt.Errorf("cpio: unknown file mode %v", fm)
	}
	if fm&os.ModeSetuid != 0 {
		h.Mode |= ModeSetuid
	}
	if fm&os.ModeSetgid != 0 {
		h.Mode |= ModeSetgid
	}
	if fm&os.ModeSticky != 0 {
		h.Mode |= ModeSticky
	}

	return h, nil
}
