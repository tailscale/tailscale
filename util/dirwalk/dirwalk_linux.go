// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirwalk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"go4.org/mem"
	"golang.org/x/sys/unix"
)

func init() {
	osWalkShallow = linuxWalkShallow
}

var dirEntPool = &sync.Pool{New: func() any { return new(linuxDirEnt) }}

func linuxWalkShallow(dirName mem.RO, fn WalkFunc) error {
	const blockSize = 8 << 10
	buf := make([]byte, blockSize) // stack-allocated; doesn't escape

	nameb := mem.Append(buf[:0], dirName)
	nameb = append(nameb, 0)

	fd, err := sysOpen(nameb)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	bufp := 0 // starting read position in buf
	nbuf := 0 // end valid data in buf

	de := dirEntPool.Get().(*linuxDirEnt)
	defer de.cleanAndPutInPool()
	de.root = dirName

	for {
		if bufp >= nbuf {
			bufp = 0
			nbuf, err = readDirent(fd, buf)
			if err != nil {
				return err
			}
			if nbuf <= 0 {
				return nil
			}
		}
		consumed, name := parseDirEnt(&de.d, buf[bufp:nbuf])
		bufp += consumed
		if len(name) == 0 || string(name) == "." || string(name) == ".." {
			continue
		}
		de.name = mem.B(name)
		if err := fn(de.name, de); err != nil {
			return err
		}
	}
}

type linuxDirEnt struct {
	root mem.RO
	d    syscall.Dirent
	name mem.RO
}

func (de *linuxDirEnt) cleanAndPutInPool() {
	de.root = mem.RO{}
	de.name = mem.RO{}
	dirEntPool.Put(de)
}

func (de *linuxDirEnt) Name() string { return de.name.StringCopy() }
func (de *linuxDirEnt) Info() (fs.FileInfo, error) {
	return os.Lstat(filepath.Join(de.root.StringCopy(), de.name.StringCopy()))
}
func (de *linuxDirEnt) IsDir() bool {
	return de.d.Type == syscall.DT_DIR
}
func (de *linuxDirEnt) Type() fs.FileMode {
	switch de.d.Type {
	case syscall.DT_BLK:
		return fs.ModeDevice // shrug
	case syscall.DT_CHR:
		return fs.ModeCharDevice
	case syscall.DT_DIR:
		return fs.ModeDir
	case syscall.DT_FIFO:
		return fs.ModeNamedPipe
	case syscall.DT_LNK:
		return fs.ModeSymlink
	case syscall.DT_REG:
		return 0
	case syscall.DT_SOCK:
		return fs.ModeSocket
	default:
		return fs.ModeIrregular // shrug
	}
}

func direntNamlen(dirent *syscall.Dirent) int {
	const fixedHdr = uint16(unsafe.Offsetof(syscall.Dirent{}.Name))
	limit := dirent.Reclen - fixedHdr
	const dirNameLen = 256 // sizeof syscall.Dirent.Name
	if limit > dirNameLen {
		limit = dirNameLen
	}
	for i := uint16(0); i < limit; i++ {
		if dirent.Name[i] == 0 {
			return int(i)
		}
	}
	panic("failed to find terminating 0 byte in dirent")
}

func parseDirEnt(dirent *syscall.Dirent, buf []byte) (consumed int, name []byte) {
	// golang.org/issue/37269
	copy(unsafe.Slice((*byte)(unsafe.Pointer(dirent)), unsafe.Sizeof(syscall.Dirent{})), buf)
	if v := unsafe.Offsetof(dirent.Reclen) + unsafe.Sizeof(dirent.Reclen); uintptr(len(buf)) < v {
		panic(fmt.Sprintf("buf size of %d smaller than dirent header size %d", len(buf), v))
	}
	if len(buf) < int(dirent.Reclen) {
		panic(fmt.Sprintf("buf size %d < record length %d", len(buf), dirent.Reclen))
	}
	consumed = int(dirent.Reclen)
	if dirent.Ino == 0 { // File absent in directory.
		return
	}
	name = unsafe.Slice((*byte)(unsafe.Pointer(&dirent.Name[0])), direntNamlen(dirent))
	return
}

func sysOpen(name []byte) (fd int, err error) {
	if len(name) == 0 || name[len(name)-1] != 0 {
		return 0, syscall.EINVAL
	}
	var dirfd int = unix.AT_FDCWD
	for {
		r0, _, e1 := syscall.Syscall(unix.SYS_OPENAT, uintptr(dirfd),
			uintptr(unsafe.Pointer(&name[0])), 0)
		if e1 == 0 {
			return int(r0), nil
		}
		if e1 == syscall.EINTR {
			// Since https://golang.org/doc/go1.14#runtime we
			// need to loop on EINTR on more places.
			continue
		}
		return 0, syscall.Errno(e1)
	}
}

func readDirent(fd int, buf []byte) (n int, err error) {
	for {
		nbuf, err := syscall.ReadDirent(fd, buf)
		if err != syscall.EINTR {
			return nbuf, err
		}
	}
}
