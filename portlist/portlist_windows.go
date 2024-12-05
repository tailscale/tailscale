// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"time"

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
	pid   uint32
}

type windowsImpl struct {
	known            map[famPort]*portMeta // inode string => metadata
	includeLocalhost bool
}

type portMeta struct {
	port Port
	keep bool
}

func newWindowsImpl(includeLocalhost bool) osImpl {
	return &windowsImpl{
		known:            map[famPort]*portMeta{},
		includeLocalhost: includeLocalhost,
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
		if !im.includeLocalhost && !e.Local.Addr().IsUnspecified() {
			continue
		}
		fp := famPort{
			proto: "tcp", // TODO(bradfitz): UDP too; add to netstat
			port:  e.Local.Port(),
			pid:   uint32(e.Pid),
		}
		pm, ok := im.known[fp]
		if ok {
			pm.keep = true
			continue
		}
		var process string
		if e.OSMetadata != nil {
			if module, err := e.OSMetadata.GetModule(); err == nil {
				process = module
			}
		}
		pm = &portMeta{
			keep: true,
			port: Port{
				Proto:   "tcp",
				Port:    e.Local.Port(),
				Process: process,
				Pid:     e.Pid,
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
