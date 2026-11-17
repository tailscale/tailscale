// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"io/fs"
	"sync"
	"syscall"

	"go4.org/mem"
	"tailscale.com/util/dirwalk"
)

// counter is a reusable counter for counting file descriptors.
type counter struct {
	n int

	// cb is the (*counter).count method value. Creating it allocates,
	// so we have to save it away and use a sync.Pool to keep currentFDs
	// amortized alloc-free.
	cb func(name mem.RO, de fs.DirEntry) error
}

var counterPool = &sync.Pool{New: func() any {
	c := new(counter)
	c.cb = c.count
	return c
}}

func (c *counter) count(name mem.RO, de fs.DirEntry) error {
	c.n++
	return nil
}

// procSelfFDFd returns a file descriptor for the /proc/self/fd
// directory, kept open for the process lifetime so that
// currentFDsFast can fstat it without allocating.
var procSelfFDFd = sync.OnceValues(func() (int, error) {
	return syscall.Open("/proc/self/fd", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
})

// currentFDsFast returns the number of open file descriptors and
// whether it was able to determine it. It uses the fact that as of
// Linux 6.2 (torvalds/linux@f1f1f2569901), the stat size of the
// /proc/self/fd directory is the number of open file descriptors.
// On older kernels the reported size is zero.
func currentFDsFast() (n int, ok bool) {
	fd, err := procSelfFDFd()
	if err != nil {
		return 0, false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, false
	}
	return int(st.Size), st.Size > 0
}

// currentFDsDirwalk returns the number of open file descriptors by
// walking /proc/self/fd. It works on all kernels but is O(n) in the
// number of open file descriptors.
func currentFDsDirwalk() int {
	c := counterPool.Get().(*counter)
	defer counterPool.Put(c)
	c.n = 0
	dirwalk.WalkShallow(mem.S("/proc/self/fd"), c.cb)
	return c.n
}

func currentFDs() int {
	if n, ok := currentFDsFast(); ok {
		return n
	}
	return currentFDsDirwalk()
}
