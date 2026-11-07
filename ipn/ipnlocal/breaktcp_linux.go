// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"log"

	"golang.org/x/sys/unix"
)

func init() {
	breakTCPConns = breakTCPConnsLinux
}

// tcpListenState is TCP_LISTEN from include/net/tcp_states.h.
const tcpListenState = 10

func breakTCPConnsLinux() error {
	fds := make([]int, 1000)
	for i := range fds {
		fds[i] = i
	}
	return breakTCPConnsLinuxFDs(fds)
}

// breakTCPConnsLinuxFDs closes those of the given file descriptors that are
// TCP sockets other than listeners.
func breakTCPConnsLinuxFDs(fds []int) error {
	var matched int
	for _, fd := range fds {
		info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil && info.State != tcpListenState {
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
