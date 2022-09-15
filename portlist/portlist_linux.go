// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"go4.org/mem"
	"golang.org/x/sys/unix"
)

// Reading the sockfiles on Linux is very fast, so we can do it often.
const pollInterval = 1 * time.Second

var sockfiles = []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}

var sawProcNetPermissionErr atomic.Bool

const (
	v6Localhost = "00000000000000000000000001000000:"
	v6Any       = "00000000000000000000000000000000:0000"
	v4Localhost = "0100007F:"
	v4Any       = "00000000:0000"
)

func listPorts() (List, error) {
	if sawProcNetPermissionErr.Load() {
		return nil, nil
	}
	var ret []Port

	var br *bufio.Reader
	for _, fname := range sockfiles {
		// Android 10+ doesn't allow access to this anymore.
		// https://developer.android.com/about/versions/10/privacy/changes#proc-net-filesystem
		// Ignore it rather than have the system log about our violation.
		if runtime.GOOS == "android" && syscall.Access(fname, unix.R_OK) != nil {
			sawProcNetPermissionErr.Store(true)
			return nil, nil
		}

		f, err := os.Open(fname)
		if os.IsPermission(err) {
			sawProcNetPermissionErr.Store(true)
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %s", fname, err)
		}
		if br == nil {
			br = bufio.NewReader(f)
		} else {
			br.Reset(f)
		}
		ports, err := parsePorts(br, filepath.Base(fname))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", fname, err)
		}
		ret = append(ret, ports...)
	}
	return ret, nil
}

// fileBase is one of "tcp", "tcp6", "udp", "udp6".
func parsePorts(r *bufio.Reader, fileBase string) ([]Port, error) {
	proto := strings.TrimSuffix(fileBase, "6")
	var ret []Port

	// skip header row
	_, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}

	fields := make([]mem.RO, 0, 20) // 17 current fields + some future slop

	wantRemote := mem.S(v4Any)
	if strings.HasSuffix(fileBase, "6") {
		wantRemote = mem.S(v6Any)
	}

	// remoteIndex is the index within a line to the remote address field.
	// -1 means not yet found.
	remoteIndex := -1

	// Add an upper bound on how many rows we'll attempt to read just
	// to make sure this doesn't consume too much of their CPU.
	// TODO(bradfitz,crawshaw): adaptively adjust polling interval as function
	// of open sockets.
	const maxRows = 1e6
	rows := 0

	// Scratch buffer for making inode strings.
	inoBuf := make([]byte, 0, 50)

	for err == nil {
		line, err := r.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rows++
		if rows >= maxRows {
			break
		}
		if len(line) == 0 {
			continue
		}

		// On the first row of output, find the index of the 3rd field (index 2),
		// the remote address. All the rows are aligned, at least until 4 billion open
		// TCP connections, per the Linux get_tcp4_sock's "%4d: " on an int i.
		if remoteIndex == -1 {
			remoteIndex = fieldIndex(line, 2)
			if remoteIndex == -1 {
				break
			}
		}

		if len(line) < remoteIndex || !mem.HasPrefix(mem.B(line).SliceFrom(remoteIndex), wantRemote) {
			// Fast path for not being a listener port.
			continue
		}

		// sl local rem ... inode
		fields = mem.AppendFields(fields[:0], mem.B(line))
		local := fields[1]
		rem := fields[2]
		inode := fields[9]

		if !rem.Equal(wantRemote) {
			// not a "listener" port
			continue
		}

		// If a port is bound to localhost, ignore it.
		// TODO: localhost is bigger than 1 IP, we need to ignore
		// more things.
		if mem.HasPrefix(local, mem.S(v4Localhost)) || mem.HasPrefix(local, mem.S(v6Localhost)) {
			continue
		}

		// Don't use strings.Split here, because it causes
		// allocations significant enough to show up in profiles.
		i := mem.IndexByte(local, ':')
		if i == -1 {
			return nil, fmt.Errorf("%q unexpectedly didn't have a colon", local.StringCopy())
		}
		portv, err := mem.ParseUint(local.SliceFrom(i+1), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%#v: %s", local.SliceFrom(9).StringCopy(), err)
		}
		inoBuf = append(inoBuf[:0], "socket:["...)
		inoBuf = mem.Append(inoBuf, inode)
		inoBuf = append(inoBuf, ']')
		ret = append(ret, Port{
			Proto: proto,
			Port:  uint16(portv),
			inode: string(inoBuf),
		})
	}

	return ret, nil
}

func addProcesses(pl []Port) ([]Port, error) {
	pm := map[string]*Port{} // by Port.inode
	for i := range pl {
		pm[pl[i].inode] = &pl[i]
	}

	err := foreachPID(func(pid string) error {
		fdPath := fmt.Sprintf("/proc/%s/fd", pid)

		// Android logs a bunch of audit violations in logcat
		// if we try to open things we don't have access
		// to. So on Android only, ask if we have permission
		// rather than just trying it to determine whether we
		// have permission.
		if runtime.GOOS == "android" && syscall.Access(fdPath, unix.R_OK) != nil {
			return nil
		}

		fdDir, err := os.Open(fdPath)
		if err != nil {
			// Can't open fd list for this pid. Maybe
			// don't have access. Ignore it.
			return nil
		}
		defer fdDir.Close()

		targetBuf := make([]byte, 64) // plenty big for "socket:[165614651]"
		for {
			fds, err := fdDir.Readdirnames(100)
			if err == io.EOF {
				return nil
			}
			if os.IsNotExist(err) {
				// This can happen if the directory we're
				// reading disappears during the run. No big
				// deal.
				return nil
			}
			if err != nil {
				return fmt.Errorf("addProcesses.readDir: %w", err)
			}
			for _, fd := range fds {
				n, err := unix.Readlink(fmt.Sprintf("/proc/%s/fd/%s", pid, fd), targetBuf)
				if err != nil {
					// Not a symlink or no permission.
					// Skip it.
					continue
				}

				pe := pm[string(targetBuf[:n])] // m[string([]byte)] avoids alloc
				if pe != nil {
					bs, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
					if err != nil {
						// Usually shouldn't happen. One possibility is
						// the process has gone away, so let's skip it.
						continue
					}

					argv := strings.Split(strings.TrimSuffix(string(bs), "\x00"), "\x00")
					pe.Process = argvSubject(argv...)
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return pl, nil
}

func foreachPID(fn func(pidStr string) error) error {
	pdir, err := os.Open("/proc")
	if err != nil {
		return err
	}
	defer pdir.Close()

	for {
		pids, err := pdir.Readdirnames(100)
		if err == io.EOF {
			return nil
		}
		if os.IsNotExist(err) {
			// This can happen if the directory we're
			// reading disappears during the run. No big
			// deal.
			return nil
		}
		if err != nil {
			return fmt.Errorf("foreachPID.readdir: %w", err)
		}

		for _, pid := range pids {
			_, err := strconv.ParseInt(pid, 10, 64)
			if err != nil {
				// not a pid, ignore it.
				// /proc has lots of non-pid stuff in it.
				continue
			}
			if err := fn(pid); err != nil {
				return err
			}
		}
	}
}

// fieldIndex returns the offset in line where the Nth field (0-based) begins, or -1
// if there aren't that many fields. Fields are separated by 1 or more spaces.
func fieldIndex(line []byte, n int) int {
	skip := 0
	for i := 0; i <= n; i++ {
		// Skip spaces.
		for skip < len(line) && line[skip] == ' ' {
			skip++
		}
		if skip == len(line) {
			return -1
		}
		if i == n {
			break
		}
		// Skip non-space.
		for skip < len(line) && line[skip] != ' ' {
			skip++
		}
	}
	return skip
}
