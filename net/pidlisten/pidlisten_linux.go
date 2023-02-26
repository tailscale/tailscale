// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pidlisten

import (
	"errors"
	"fmt"
	"go4.org/mem"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"tailscale.com/util/dirwalk"

	"github.com/vishvananda/netlink"
)

// NewPIDListener wraps a net.Listener so that it only accepts connections from the current process.
func NewPIDListener(ln net.Listener) net.Listener {
	return &listener{ln: ln}
}

var errFoundSocket = errors.New("found socket")

func checkPIDLocal(conn net.Conn) (bool, error) {
	remoteAddr := conn.RemoteAddr()
	var remoteIP net.IP
	switch remoteAddr.Network() {
	case "tcp":
		remoteIP = remoteAddr.(*net.TCPAddr).IP
	case "udp":
		remoteIP = remoteAddr.(*net.UDPAddr).IP
	default:
		return false, nil
	}
	if !remoteIP.IsLoopback() {
		return false, nil
	}

	// You can look up a net.Conn in both directions.
	// There are different inodes for remote->local and local->remote.
	// We want to look up the starting side of the net.Conn and check
	// that its inode belongs to the current PID.
	s, err := netlink.SocketGet(conn.RemoteAddr(), conn.LocalAddr())
	if err != nil {
		return false, err
	}

	want := fmt.Sprintf("socket:[%d]", s.INode)
	dir := fmt.Sprintf("/proc/%d/fd", os.Getpid())
	err = dirwalk.WalkShallow(mem.S(dir), func(name mem.RO, de fs.DirEntry) error {
		n, err := os.Readlink(filepath.Join(dir, name.StringCopy()))
		if err == nil && want == n {
			return errFoundSocket
		}
		return nil
	})
	if err == errFoundSocket {
		return true, nil
	}
	return false, err
}
