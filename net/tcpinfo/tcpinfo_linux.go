// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tcpinfo

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func rttImpl(conn *net.TCPConn) (time.Duration, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var (
		tcpInfo *unix.TCPInfo
		sysErr  error
	)
	err = rawConn.Control(func(fd uintptr) {
		tcpInfo, sysErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil {
		return 0, err
	} else if sysErr != nil {
		return 0, sysErr
	}

	return time.Duration(tcpInfo.Rtt) * time.Microsecond, nil
}
