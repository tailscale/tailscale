// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/syncs"
)

// Reading the sockfiles on Linux is very fast, so we can do it often.
const pollInterval = 1 * time.Second

var sockfiles = []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}

var sawProcNetPermissionErr syncs.AtomicBool

const (
	v6Localhost = "00000000000000000000000001000000:"
	v6Any       = "00000000000000000000000000000000:0000"
	v4Localhost = "0100007F:"
	v4Any       = "00000000:0000"
)

func listPorts() (List, error) {
	if sawProcNetPermissionErr.Get() {
		return nil, nil
	}
	l := []Port{}

	for _, fname := range sockfiles {
		proto := strings.TrimSuffix(filepath.Base(fname), "6")

		// Android 10+ doesn't allow access to this anymore.
		// https://developer.android.com/about/versions/10/privacy/changes#proc-net-filesystem
		// Ignore it rather than have the system log about our violation.
		if runtime.GOOS == "android" && syscall.Access(fname, unix.R_OK) != nil {
			sawProcNetPermissionErr.Set(true)
			return nil, nil
		}

		f, err := os.Open(fname)
		if os.IsPermission(err) {
			sawProcNetPermissionErr.Set(true)
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %s", fname, err)
		}
		defer f.Close()
		r := bufio.NewReader(f)

		ports, err := parsePorts(r, proto)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", fname, err)
		}

		l = append(l, ports...)
	}

	sort.Slice(l, func(i, j int) bool {
		return (&l[i]).lessThan(&l[j])
	})

	return l, nil
}

func parsePorts(r *bufio.Reader, proto string) ([]Port, error) {
	var ret []Port

	// skip header row
	_, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	for err == nil {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// sl local rem ... inode
		words := strings.Fields(line)
		local := words[1]
		rem := words[2]
		inode := words[9]

		// If a port is bound to localhost, ignore it.
		// TODO: localhost is bigger than 1 IP, we need to ignore
		// more things.
		if strings.HasPrefix(local, v4Localhost) || strings.HasPrefix(local, v6Localhost) {
			continue
		}
		if rem != v4Any && rem != v6Any {
			// not a "listener" port
			continue
		}

		// Don't use strings.Split here, because it causes
		// allocations significant enough to show up in profiles.
		i := strings.IndexByte(local, ':')
		if i == -1 {
			return nil, fmt.Errorf("%q unexpectedly didn't have a colon", local)
		}
		portv, err := strconv.ParseUint(local[i+1:], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%#v: %s", local[9:], err)
		}
		inodev := fmt.Sprintf("socket:[%s]", inode)
		ret = append(ret, Port{
			Proto: proto,
			Port:  uint16(portv),
			inode: inodev,
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
					bs, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
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
