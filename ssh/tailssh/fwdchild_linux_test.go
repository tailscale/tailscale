// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// peerCredUID returns the effective uid of the peer of a connected unix
// socket, read from the listening side with SO_PEERCRED.
func peerCredUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix conn")
	}
	f, err := uc.File()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	u, err := unix.GetsockoptUcred(int(f.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(u.Uid), nil
}

// dumpChildFdsTo appends this process's fd table to the file at path,
// one "fd <n> flags <oct> -> <target>" line per descriptor, wrapped
// in a BEGIN/END block tagged with tag. It runs at re-exec'd helper-child
// entry (the TS_TEST_SSH_FWD_FDINFO knob for the one-shot fwd child,
// the INCUB-FDS-DUMP=<path> argv marker for the session child's
// incubator), before the child performs its op.
//
// Readlink targets show any leaked pty end. The fdinfo flags field
// separates inherited descriptors from the observee's own runtime
// bookkeeping, which always carries FD_CLOEXEC.
//
// The enumeration runs on an explicitly opened dirfd whose number is
// skipped, along with the dump file's own descriptor; descriptors that
// vanish between the listing and the read are skipped as transient.
func dumpChildFdsTo(path, tag string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		return
	}
	defer f.Close()
	const fdDir = "/proc/self/fd"
	dirfd, err := unix.Open(fdDir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return
	}
	defer unix.Close(dirfd)

	// First pass: snapshot the fd numbers via getdents on the known dirfd.
	var fdnums []int
	buf := make([]byte, 16384)
	for {
		n, err := unix.Getdents(dirfd, buf)
		if n <= 0 {
			break
		}
		_, _, names := unix.ParseDirent(buf[:n], -1, nil)
		for _, name := range names {
			if fd, err := strconv.Atoi(name); err == nil && fd != dirfd && fd != int(f.Fd()) {
				fdnums = append(fdnums, fd)
			}
		}
		if err != nil && err != io.EOF {
			break
		}
	}
	slices.Sort(fdnums)

	// Second pass: readlink and fdinfo flags for each listed number.
	var sb strings.Builder
	fmt.Fprintf(&sb, "BEGIN %s pid %d\n", tag, os.Getpid())
	for _, fd := range fdnums {
		target, lerr := os.Readlink(filepath.Join(fdDir, strconv.Itoa(fd)))
		if lerr != nil {
			if errors.Is(lerr, fs.ErrNotExist) {
				continue // transient: closed between the listing and this read
			}
			target = lerr.Error()
		}
		flags := ""
		if info, ierr := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd))); ierr == nil {
			for _, line := range strings.Split(string(info), "\n") {
				if v, ok := strings.CutPrefix(line, "flags:"); ok {
					flags = strings.TrimSpace(v)
					break
				}
			}
		}
		fmt.Fprintf(&sb, "fd %d flags %s -> %s\n", fd, flags, target)
	}
	fmt.Fprintf(&sb, "END %s\n", tag)
	_, _ = f.WriteString(sb.String())
}
