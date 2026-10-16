// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sockopts

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

// BindUDPGroup opens up to n UDP sockets sharing one local port,
// across which the kernel spreads inbound datagrams.
// Network must be "udp", "udp4", or "udp6".
//
// Control is applied after BindUDPGroup's own hook has set SO_REUSEPORT.
// It may be nil.
//
// BindUDPGroup returns at least one socket and logs the shortfall.
// It returns one socket and logs nothing where [CanShareUDPPort] is false.
// An error is reported only when it could not bind even one socket.
// The caller owns every returned socket.
func BindUDPGroup(ctx context.Context, logf logger.Logf, n int, control ControlFunc, network string, port uint16) (pconns []nettype.PacketConn, boundPort uint16, err error) {
	if n < 1 {
		panic(fmt.Sprintf("must bind at least one socket, %d was requested", n))
	}
	first, err := listenUDP(ctx, control, network, port)
	if err != nil {
		return nil, 0, err
	}
	boundPort = uint16(first.LocalAddr().(*net.UDPAddr).Port)
	pconns = append(make([]nettype.PacketConn, 0, n), first)
	if n == 1 || !CanShareUDPPort {
		return pconns, boundPort, nil
	}

	// The first socket binds the port exclusively, then shares it. The rest
	// set SO_REUSEPORT before binding, joining it.
	rc, err := RawConn(first)
	if err == nil {
		err = SetReusePort(rc)
	}
	if err != nil {
		logf("sharing bound port %d: %v", boundPort, err)
		return pconns, boundPort, nil
	}
	joining := func(network, address string, c syscall.RawConn) error {
		if err := SetReusePort(c); err != nil {
			return err
		}
		if control != nil {
			return control(network, address, c)
		}
		return nil
	}
	for len(pconns) < n {
		pconn, err := listenUDP(ctx, joining, network, boundPort)
		if err != nil {
			logf("binding socket %d of %d on port %d: %v", len(pconns)+1, n, boundPort, err)
			break
		}
		pconns = append(pconns, pconn)
	}
	return pconns, boundPort, nil
}

func listenUDP(ctx context.Context, control ControlFunc, network string, port uint16) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: control}
	pconn, err := lc.ListenPacket(ctx, network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	uc, ok := pconn.(*net.UDPConn)
	if !ok {
		pconn.Close()
		return nil, fmt.Errorf("%q (%T) is not a UDP network", network, pconn)
	}
	return uc, nil
}
