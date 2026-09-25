// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

// setReusePort sets SO_REUSEPORT on rc's socket. It must be called before
// bind.
func setReusePort(rc syscall.RawConn) error {
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}

// peerConnSupported reports whether this kernel delivers a datagram to a
// connected UDP socket in preference to an unconnected one sharing its port
// via SO_REUSEPORT, which [peerConn] depends on.
//
// Darwin has always preferred the exact 4-tuple match. Linux only does so
// since torvalds/linux@acdcecc61285 (5.4, backported to 4.19.75); older
// kernels hash across the reuseport group and misdeliver. Rather than parse
// kernel versions, this exchanges a few datagrams over loopback and checks
// where they land.
func peerConnSupported(logf logger.Logf) bool {
	err := peerConnSelfTest()
	if err != nil {
		logf("magicsock: connected per-peer sockets unsupported here: %v", err)
		return false
	}
	return true
}

func peerConnSelfTest() error {
	lc := net.ListenConfig{}
	wrapReusePort(&lc)
	ctx := context.Background()

	// main stands in for the wildcard main magicsock socket.
	main, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("listen main: %w", err)
	}
	defer main.Close()
	port := main.LocalAddr().(*net.UDPAddr).Port

	// peer and other stand in for two remote peers.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("listen peer: %w", err)
	}
	defer peer.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("listen other: %w", err)
	}
	defer other.Close()

	// connected stands in for a peerConn: same local port as main,
	// connected to peer.
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: port}}
	d.Control = func(network, address string, rc syscall.RawConn) error {
		return setReusePort(rc)
	}
	connected, err := d.DialContext(ctx, "udp4", peer.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("dial connected: %w", err)
	}
	defer connected.Close()

	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	deadline := time.Now().Add(2 * time.Second)
	connected.SetReadDeadline(deadline)
	main.SetReadDeadline(deadline)
	buf := make([]byte, 16)

	// A datagram from peer must land on connected, not main.
	if _, err := peer.WriteToUDP([]byte("peer"), dst); err != nil {
		return fmt.Errorf("send from peer: %w", err)
	}
	n, err := connected.Read(buf)
	if err != nil {
		return fmt.Errorf("connected socket did not receive peer's datagram: %w", err)
	}
	if string(buf[:n]) != "peer" {
		return fmt.Errorf("connected socket got %q, want %q", buf[:n], "peer")
	}

	// A datagram from other must still land on main.
	if _, err := other.WriteToUDP([]byte("other"), dst); err != nil {
		return fmt.Errorf("send from other: %w", err)
	}
	n, _, err = main.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("main socket did not receive other's datagram: %w", err)
	}
	if string(buf[:n]) != "other" {
		if string(buf[:n]) == "peer" {
			return errors.New("kernel delivered peer's datagram to the unconnected socket")
		}
		return fmt.Errorf("main socket got %q, want %q", buf[:n], "other")
	}
	return nil
}
