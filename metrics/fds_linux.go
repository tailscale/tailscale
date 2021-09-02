// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func currentFDs() int {
	fd, err := openProcSelfFD()
	if err != nil {
		return 0
	}
	defer syscall.Close(fd)

	count := 0

	const blockSize = 8 << 10
	buf := make([]byte, blockSize) // stack-allocated; doesn't escape
	bufp := 0                      // starting read position in buf
	nbuf := 0                      // end valid data in buf
	dirent := &syscall.Dirent{}
	for {
		if bufp >= nbuf {
			bufp = 0
			nbuf, err = readDirent(fd, buf)
			if err != nil {
				log.Printf("currentFDs: readDirent: %v", err)
				return 0
			}
			if nbuf <= 0 {
				return count
			}
		}
		consumed, name := parseDirEnt(dirent, buf[bufp:nbuf])
		bufp += consumed
		if len(name) == 0 || string(name) == "." || string(name) == ".." {
			continue
		}
		count++
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

var procSelfFDName = []byte("/proc/self/fd\x00")

func openProcSelfFD() (fd int, err error) {
	var dirfd int = unix.AT_FDCWD
	for {
		r0, _, e1 := syscall.Syscall(unix.SYS_OPENAT, uintptr(dirfd),
			uintptr(unsafe.Pointer(&procSelfFDName[0])), 0)
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
