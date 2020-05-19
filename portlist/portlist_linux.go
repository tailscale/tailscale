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
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Reading the sockfiles on Linux is very fast, so we can do it often.
const pollInterval = 1 * time.Second

// TODO(apenwarr): Include IPv6 ports eventually.
// Right now we don't route IPv6 anyway so it's better to exclude them.
var sockfiles = []string{"/proc/net/tcp", "/proc/net/udp"}
var protos = []string{"tcp", "udp"}

func listPorts() (List, error) {
	l := []Port{}

	for pi, fname := range sockfiles {
		proto := protos[pi]

		f, err := os.Open(fname)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", fname, err)
		}
		defer f.Close()
		r := bufio.NewReader(f)

		// skip header row
		_, err = r.ReadString('\n')
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

			// If a port is bound to 127.0.0.1, ignore it.
			if strings.HasPrefix(local, "0100007F:") {
				continue
			}
			if rem != "00000000:0000" {
				// not a "listener" port
				continue
			}

			portv, err := strconv.ParseUint(local[9:], 16, 16)
			if err != nil {
				return nil, fmt.Errorf("%#v: %s", local[9:], err)
			}
			inodev := fmt.Sprintf("socket:[%s]", inode)
			l = append(l, Port{
				Proto: proto,
				Port:  uint16(portv),
				inode: inodev,
			})
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return (&l[i]).lessThan(&l[j])
	})

	return l, nil
}

func addProcesses(pl []Port) ([]Port, error) {
	pm := map[string]*Port{} // by Port.inode
	for i := range pl {
		pm[pl[i].inode] = &pl[i]
	}

	err := foreachPID(func(pid string) error {
		fdDir, err := os.Open(fmt.Sprintf("/proc/%s/fd", pid))
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

				// TODO(apenwarr): use /proc/*/cmdline instead of /comm?
				// Unsure right now whether users will want the extra detail
				// or not.
				pe := pm[string(targetBuf[:n])] // m[string([]byte)] avoids alloc
				if pe != nil {
					comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
					if err != nil {
						// Usually shouldn't happen. One possibility is
						// the process has gone away, so let's skip it.
						continue
					}
					pe.Process = strings.TrimSpace(string(comm))
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
