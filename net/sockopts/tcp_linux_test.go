// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sockopts

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTCPConfigApply(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := new(net.Dialer)
	d.SetMultipathTCP(false)
	outgoing, err := d.DialContext(t.Context(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	incoming, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()

	for name, c := range map[string]*net.TCPConn{"dialed": outgoing.(*net.TCPConn), "accepted": incoming} {
		t.Run(name, func(t *testing.T) {
			rc, err := c.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			get := func(level, opt int) int {
				t.Helper()
				var value int
				var sockErr error
				if err := rc.Control(func(fd uintptr) {
					value, sockErr = unix.GetsockoptInt(int(fd), level, opt)
				}); err != nil {
					t.Fatal(err)
				}
				if sockErr != nil {
					t.Fatal(sockErr)
				}
				return value
			}
			check := func(level, opt, want int) {
				t.Helper()
				if got := get(level, opt); got != want {
					t.Errorf("socket option (%d, %d) = %d; want %d", level, opt, got, want)
				}
			}
			timeout := 45 * time.Second
			cfg := TCPConfig{
				KeepAlive: &net.KeepAliveConfig{
					Enable: true, Idle: 60 * time.Second, Interval: 10 * time.Second, Count: 3,
				},
				UserTimeout: &timeout,
			}
			for _, config := range []TCPConfig{cfg, {}} {
				result := config.Apply(c)
				if result.KeepAlive != nil || result.UserTimeout != nil {
					t.Fatalf("Apply: %+v", result)
				}
				check(unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
				check(unix.SOL_TCP, unix.TCP_KEEPIDLE, 60)
				check(unix.SOL_TCP, unix.TCP_KEEPINTVL, 10)
				check(unix.SOL_TCP, unix.TCP_KEEPCNT, 3)
				check(unix.SOL_TCP, unix.TCP_USER_TIMEOUT, 45000)
			}

			// A rejected user timeout must not prevent an independent
			// keepalive change, or overwrite the previous timeout.
			invalid := -time.Second
			result := (TCPConfig{
				KeepAlive: &net.KeepAliveConfig{Enable: false}, UserTimeout: &invalid,
			}).Apply(c)
			if result.KeepAlive != nil || result.UserTimeout == nil {
				t.Fatalf("invalid timeout: %+v", result)
			}
			check(unix.SOL_SOCKET, unix.SO_KEEPALIVE, 0)
			check(unix.SOL_TCP, unix.TCP_USER_TIMEOUT, 45000)

			// A failed keepalive setting must not prevent the timeout from
			// being applied. Linux rejects probe counts above 127.
			timeout = 30 * time.Second
			result = (TCPConfig{
				KeepAlive: &net.KeepAliveConfig{Enable: true, Count: 128}, UserTimeout: &timeout,
			}).Apply(c)
			if result.KeepAlive == nil || result.UserTimeout != nil {
				t.Fatalf("invalid keepalive count: %+v", result)
			}
			check(unix.SOL_TCP, unix.TCP_USER_TIMEOUT, 30000)

			zero := time.Duration(0)
			result = (TCPConfig{UserTimeout: &zero}).Apply(c)
			if result.UserTimeout != nil {
				t.Fatal(result.UserTimeout)
			}
			check(unix.SOL_TCP, unix.TCP_USER_TIMEOUT, 0)
		})
	}
}
