// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/util/mak"
)

func init() {
	newOSImpl = newLinuxImpl
	// Reading the sockfiles on Linux is very fast, so we can do it often.
	pollInterval = 1 * time.Second
}

type linuxImpl struct {
	procNetFiles []*os.File // seeked to start & reused between calls

	known map[string]*portMeta // inode string => metadata
	br    *bufio.Reader
}

type portMeta struct {
	port          Port
	pid           int
	keep          bool
	needsProcName bool
}

func newLinuxImplBase() *linuxImpl {
	return &linuxImpl{
		br:    bufio.NewReader(eofReader),
		known: map[string]*portMeta{},
	}
}

func newLinuxImpl() osImpl {
	li := newLinuxImplBase()
	for _, name := range []string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
		"/proc/net/udp",
		"/proc/net/udp6",
	} {
		f, err := os.Open(name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Printf("portlist warning; ignoring: %v", err)
			continue
		}
		li.procNetFiles = append(li.procNetFiles, f)
	}
	return li
}

func (li *linuxImpl) Close() error {
	for _, f := range li.procNetFiles {
		f.Close()
	}
	li.procNetFiles = nil
	return nil
}

const (
	v6Localhost = "00000000000000000000000001000000:"
	v6Any       = "00000000000000000000000000000000:0000"
	v4Localhost = "0100007F:"
	v4Any       = "00000000:0000"
)

var eofReader = bytes.NewReader(nil)

func (li *linuxImpl) AppendListeningPorts(base []Port) ([]Port, error) {
	if runtime.GOOS == "android" {
		// Android 10+ doesn't allow access to this anymore.
		// https://developer.android.com/about/versions/10/privacy/changes#proc-net-filesystem
		// Ignore it rather than have the system log about our violation.
		return nil, nil
	}

	br := li.br
	defer br.Reset(eofReader)

	// Start by marking all previous known ports as gone. If this mark
	// bit is still false later, we'll remove them.
	for _, pm := range li.known {
		pm.keep = false
	}

	for _, f := range li.procNetFiles {
		name := f.Name()
		_, err := f.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		br.Reset(f)
		err = li.parseProcNetFile(br, filepath.Base(name))
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", name, err)
		}
	}

	// Delete ports that aren't open any longer.
	// And see if there are any process names we need to look for.
	var needProc map[string]*portMeta
	for inode, pm := range li.known {
		if !pm.keep {
			delete(li.known, inode)
			continue
		}
		if pm.needsProcName {
			mak.Set(&needProc, inode, pm)
		}
	}
	err := li.findProcessNames(needProc)
	if err != nil {
		return nil, err
	}

	ret := base
	for _, pm := range li.known {
		ret = append(ret, pm.port)
	}
	return sortAndDedup(ret), nil
}

// fileBase is one of "tcp", "tcp6", "udp", "udp6".
func (li *linuxImpl) parseProcNetFile(r *bufio.Reader, fileBase string) error {
	proto := strings.TrimSuffix(fileBase, "6")

	// skip header row
	_, err := r.ReadSlice('\n')
	if err != nil {
		return err
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
			return err
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
			return fmt.Errorf("%q unexpectedly didn't have a colon", local.StringCopy())
		}
		portv, err := mem.ParseUint(local.SliceFrom(i+1), 16, 16)
		if err != nil {
			return fmt.Errorf("%#v: %s", local.SliceFrom(9).StringCopy(), err)
		}
		inoBuf = append(inoBuf[:0], "socket:["...)
		inoBuf = mem.Append(inoBuf, inode)
		inoBuf = append(inoBuf, ']')

		if pm, ok := li.known[string(inoBuf)]; ok {
			pm.keep = true
			// Rest should be unchanged.
		} else {
			li.known[string(inoBuf)] = &portMeta{
				needsProcName: true,
				keep:          true,
				port: Port{
					Proto: proto,
					Port:  uint16(portv),
				},
			}
		}
	}

	return nil
}

// errDone is an internal sentinel error that we found everything we were looking for.
var errDone = errors.New("done")

// need is keyed by inode string.
func (li *linuxImpl) findProcessNames(need map[string]*portMeta) error {
	if len(need) == 0 {
		return nil
	}
	defer func() {
		// Anything we didn't find, give up on and don't try to look for it later.
		for _, pm := range need {
			pm.needsProcName = false
		}
	}()

	var pathBuf []byte

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
				pathBuf = fmt.Appendf(pathBuf[:0], "/proc/%s/fd/%s\x00", pid, fd)
				n, ok := readlink(pathBuf, targetBuf)
				if !ok {
					// Not a symlink or no permission.
					// Skip it.
					continue
				}

				pe := need[string(targetBuf[:n])] // m[string([]byte)] avoids alloc
				if pe != nil {
					bs, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
					if err != nil {
						// Usually shouldn't happen. One possibility is
						// the process has gone away, so let's skip it.
						continue
					}

					argv := strings.Split(strings.TrimSuffix(string(bs), "\x00"), "\x00")
					if p, err := strconv.Atoi(pid); err == nil {
						pe.pid = p
					}
					pe.port.Process = argvSubject(argv...)
					pe.needsProcName = false
					delete(need, string(targetBuf[:n]))
					if len(need) == 0 {
						return errDone
					}
				}
			}
		}
	})
	if err == errDone {
		return nil
	}
	return err
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

// path must be null terminated.
func readlink(path, buf []byte) (n int, ok bool) {
	if len(buf) == 0 || len(path) < 2 || path[len(path)-1] != 0 {
		return 0, false
	}
	var dirfd int = unix.AT_FDCWD
	r0, _, e1 := unix.Syscall6(unix.SYS_READLINKAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(&path[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0)
	n = int(r0)
	if e1 != 0 {
		return 0, false
	}
	return n, true
}
