// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"tailscale.com/net/netstat"
)

func init() {
	newOSImpl = newWindowsImpl
	// The portlist poller used to fork on Windows, which is insanely expensive,
	// so historically we only did this every 5 seconds on Windows. Maybe we
	// could reduce it down to 1 seconds like Linux, but nobody's benchmarked as
	// of 2022-11-04.
	pollInterval = 5 * time.Second
}

type famPort struct {
	proto string
	port  uint16
	pid   uintptr
}

type windowsImpl struct {
	known map[famPort]*portMeta // inode string => metadata
}

type portMeta struct {
	port Port
	keep bool
}

func newWindowsImpl() osImpl {
	return &windowsImpl{
		known: map[famPort]*portMeta{},
	}
}

func (*windowsImpl) Close() error { return nil }

func (im *windowsImpl) AppendListeningPorts(base []Port) ([]Port, error) {
	// TODO(bradfitz): netstat.Get makes a bunch of garbage. Add an Append-style
	// API to that package instead/additionally.
	tab, err := netstat.Get()
	if err != nil {
		return nil, err
	}

	for _, pm := range im.known {
		pm.keep = false
	}

	ret := base
	for _, e := range tab.Entries {
		if e.State != "LISTEN" {
			continue
		}
		if !e.Local.Addr().IsUnspecified() {
			continue
		}
		fp := famPort{
			proto: "tcp", // TODO(bradfitz): UDP too; add to netstat
			port:  e.Local.Port(),
			pid:   uintptr(e.Pid),
		}
		pm, ok := im.known[fp]
		if ok {
			pm.keep = true
			continue
		}
		pm = &portMeta{
			keep: true,
			port: Port{
				Proto:   "tcp",
				Port:    e.Local.Port(),
				Process: procNameOfPid(e.Pid),
			},
		}
		im.known[fp] = pm
	}

	for k, m := range im.known {
		if !m.keep {
			delete(im.known, k)
			continue
		}
		ret = append(ret, m.port)
	}
	return sortAndDedup(ret), nil
}

func procNameOfPid(pid int) string {
	const da = windows.PROCESS_QUERY_LIMITED_INFORMATION
	h, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)

	var buf [512]uint16
	var size = uint32(len(buf))
	if err := windows.QueryFullProcessImageName(windows.Handle(h), 0, &buf[0], &size); err != nil {
		return ""
	}
	name := filepath.Base(windows.UTF16ToString(buf[:]))
	if name == "." {
		return ""
	}
	name = strings.TrimSuffix(name, ".exe")
	name = strings.TrimSuffix(name, ".EXE")
	return name
}
