// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"log"

	"golang.org/x/sys/unix"
)

func init() {
	breakTCPConns = breakTCPConnsDarwin
}

// tcpsListen is TCPS_LISTEN from <netinet/tcp_fsm.h>.
const tcpsListen = 1

func breakTCPConnsDarwin() error {
	var matched int
	for fd := range 1000 {
		info, err := unix.GetsockoptTCPConnectionInfo(fd, unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
		if err == nil && info.State != tcpsListen {
			matched++
			err = unix.Close(fd)
			log.Printf("debug: closed TCP fd %v: %v", fd, err)
		}
	}
	if matched == 0 {
		log.Printf("debug: no TCP connections found")
	}
	return nil
}
