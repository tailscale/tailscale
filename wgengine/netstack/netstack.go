// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netstack doesn't build on 32-bit machines (https://github.com/google/gvisor/issues/5241)
// +build amd64 arm64 ppc64le riscv64 s390x

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"inet.af/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/tstun"
)

func Impl(logf logger.Logf, tundev *tstun.TUN, e wgengine.Engine, mc *magicsock.Conn) error {
	if mc == nil {
		return errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return errors.New("nil tundev")
	}
	if logf == nil {
		return errors.New("nil logger")
	}
	if e == nil {
		return errors.New("nil Engine")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol(), icmp.NewProtocol4()},
	})

	const mtu = 1500
	linkEP := channel.New(512, mtu, "")

	const nicID = 1
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		log.Fatal(err)
	}

	ipstack.AddAddress(nicID, ipv4.ProtocolNumber, tcpip.Address(net.ParseIP("100.96.188.101").To4()))

	// Add 0.0.0.0/0 default route.
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	// use Forwarder to accept any connection from stack
	fwd := tcp.NewForwarder(ipstack, 0, 16, func(r *tcp.ForwarderRequest) {
		logf("XXX ForwarderRequest: %v", r)
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		c := gonet.NewTCPConn(&wq, ep)
		// TCP echo
		go echo(c, e, mc)

	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	go func() {
		for {
			packetInfo, ok := linkEP.ReadContext(context.Background())
			if !ok {
				logf("XXX ReadContext-for-write = ok=false")
				continue
			}
			pkt := packetInfo.Pkt
			hdrNetwork := pkt.NetworkHeader()
			hdrTransport := pkt.TransportHeader()

			full := make([]byte, 0, pkt.Size())
			full = append(full, hdrNetwork.View()...)
			full = append(full, hdrTransport.View()...)
			full = append(full, pkt.Data.ToView()...)

			logf("XXX packet Write out: % x", full)
			if err := tundev.InjectOutbound(full); err != nil {
				log.Printf("netstack inject outbound: %v", err)
				return
			}

		}
	}()

	tundev.PostFilterIn = func(p *packet.Parsed, t *tstun.TUN) filter.Response {
		var pn tcpip.NetworkProtocolNumber
		switch p.IPVersion {
		case 4:
			pn = header.IPv4ProtocolNumber
		case 6:
			pn = header.IPv6ProtocolNumber
		}
		logf("XXX packet in (from %v): % x", p.Src, p.Buffer())
		vv := buffer.View(append([]byte(nil), p.Buffer()...)).ToVectorisedView()
		packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: vv,
		})
		linkEP.InjectInbound(pn, packetBuf)
		return filter.Accept
	}
	return nil
}

func echo(c *gonet.TCPConn, e wgengine.Engine, mc *magicsock.Conn) {
	defer c.Close()
	src, _ := netaddr.FromStdIP(c.RemoteAddr().(*net.TCPAddr).IP)
	who := ""
	if n, u, ok := mc.WhoIs(src); ok {
		who = fmt.Sprintf("%v from %v", u.DisplayName, n.Name)
	}
	fmt.Fprintf(c, "Hello, %s! Thanks for connecting to me on port %v (Try other ports too!)\nEchoing...\n",
		who,
		c.LocalAddr().(*net.TCPAddr).Port)
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			log.Printf("Err: %v", err)
			break
		}
		c.Write(buf[:n])
	}
	log.Print("Connection closed")
}
