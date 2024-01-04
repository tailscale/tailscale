// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/util/dirwalk"
	"tailscale.com/util/mak"
)

func init() {
	newOSImpl = newLinuxImpl
	// Reading the sockfiles on Linux is very fast, so we can do it often.
	pollInterval = 1 * time.Second
}

type linuxImpl struct {
	procNetFiles    []*os.File // seeked to start & reused between calls
	readlinkPathBuf []byte

	known            map[string]*portMeta // inode string => metadata
	br               *bufio.Reader
	includeLocalhost bool
}

type portMeta struct {
	port          Port
	pid           int
	keep          bool
	needsProcName bool
}

func newLinuxImplBase(includeLocalhost bool) *linuxImpl {
	return &linuxImpl{
		br:               bufio.NewReader(eofReader),
		known:            map[string]*portMeta{},
		includeLocalhost: includeLocalhost,
	}
}

func newLinuxImpl(includeLocalhost bool) osImpl {
	li := newLinuxImplBase(includeLocalhost)
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

	for {
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
		if !li.includeLocalhost && (mem.HasPrefix(local, mem.S(v4Localhost)) || mem.HasPrefix(local, mem.S(v6Localhost))) {
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

	err := foreachPID(func(pid mem.RO) error {
		var procBuf [128]byte
		fdPath := mem.Append(procBuf[:0], mem.S("/proc/"))
		fdPath = mem.Append(fdPath, pid)
		fdPath = mem.Append(fdPath, mem.S("/fd"))

		// Android logs a bunch of audit violations in logcat
		// if we try to open things we don't have access
		// to. So on Android only, ask if we have permission
		// rather than just trying it to determine whether we
		// have permission.
		if runtime.GOOS == "android" && syscall.Access(string(fdPath), unix.R_OK) != nil {
			return nil
		}

		dirwalk.WalkShallow(mem.B(fdPath), func(fd mem.RO, de fs.DirEntry) error {
			targetBuf := make([]byte, 64) // plenty big for "socket:[165614651]"

			linkPath := li.readlinkPathBuf[:0]
			linkPath = fmt.Appendf(linkPath, "/proc/")
			linkPath = mem.Append(linkPath, pid)
			linkPath = append(linkPath, "/fd/"...)
			linkPath = mem.Append(linkPath, fd)
			linkPath = append(linkPath, 0) // terminating NUL
			li.readlinkPathBuf = linkPath  // to reuse its buffer next time
			n, ok := readlink(linkPath, targetBuf)
			if !ok {
				// Not a symlink or no permission.
				// Skip it.
				return nil
			}

			pe := need[string(targetBuf[:n])] // m[string([]byte)] avoids alloc
			if pe == nil {
				return nil
			}
			bs, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid.StringCopy()))
			if err != nil {
				// Usually shouldn't happen. One possibility is
				// the process has gone away, so let's skip it.
				return nil
			}

			argv := strings.Split(strings.TrimSuffix(string(bs), "\x00"), "\x00")
			if p, err := mem.ParseInt(pid, 10, 0); err == nil {
				pe.pid = int(p)
			}
			pe.port.Process = argvSubject(argv...)
			pid64, _ := mem.ParseInt(pid, 10, 0)
			pe.port.Pid = int(pid64)
			pe.needsProcName = false
			delete(need, string(targetBuf[:n]))
			if len(need) == 0 {
				return errDone
			}
			return nil
		})
		return nil
	})
	if err == errDone {
		return nil
	}
	return err
}

func foreachPID(fn func(pidStr mem.RO) error) error {
	err := dirwalk.WalkShallow(mem.S("/proc"), func(name mem.RO, de fs.DirEntry) error {
		if !isNumeric(name) {
			return nil
		}
		return fn(name)
	})
	if os.IsNotExist(err) {
		// This can happen if the directory we're
		// reading disappears during the run. No big
		// deal.
		return nil
	}
	return err
}

func isNumeric(s mem.RO) bool {
	for i, n := 0, s.Len(); i < n; i++ {
		b := s.At(i)
		if b < '0' || b > '9' {
			return false
		}
	}
	return s.Len() > 0
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
