// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBreakTCPConnsKeepsListeners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			c.Read(buf)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Use dup'd fds so closing them doesn't disturb the Go net objects.
	lf, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	cf, err := conn.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Close()
	lfd, cfd := int(lf.Fd()), int(cf.Fd())

	if err := breakTCPConnsLinuxFDs([]int{lfd, cfd}); err != nil {
		t.Fatal(err)
	}

	if _, err := unix.GetsockoptTCPInfo(lfd, unix.IPPROTO_TCP, unix.TCP_INFO); err != nil {
		t.Errorf("listening socket fd was closed: %v", err)
	}
	if _, err := unix.GetsockoptTCPInfo(cfd, unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
		t.Errorf("established connection fd was not closed")
	}
}
