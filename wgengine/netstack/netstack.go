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
	"tailscale.com/types/netmap"
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	const mtu = 1500
	linkEP := channel.New(512, mtu, "")

	const nicID = 1
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		log.Fatal(err)
	}

	sendRequest := func() {
		var localIP tcpip.Address
		for _, ip := range ipstack.AllAddresses()[nicID] {
			if ip.Protocol == ipv4.ProtocolNumber {
				localIP = ip.AddressWithPrefix.Address.To4()
				break
			}
		}

		if localIP == "" {
			log.Fatalf("No IPv4 local addresses!")
		}

		/*
			// required for UDP
			localAddress := tcpip.FullAddress{
				NIC:  nicID,
				Addr: localIP,
				Port: 0,
			}*/
		remoteAddress := tcpip.FullAddress{
			NIC:  nicID,
			Addr: localIP,
			Port: 4242,
		}

		writerCompletedCh := make(chan struct{})

		/*conn, connErr := gonet.DialUDP(ipstack, &localAddress, &remoteAddress, ipv4.ProtocolNumber)
		if connErr != nil {
			log.Fatalf("netstack could not dial UDP, error: %v", connErr)
		}*/
		conn, cerr := gonet.DialTCP(ipstack, remoteAddress, ipv4.ProtocolNumber)
		if cerr != nil {
			log.Fatalf("netstack: could not dial, error %v", cerr)
		} else {
			logf("netstack: dialed!")
		}

		go func() {
			defer close(writerCompletedCh)

			_, err := conn.Write([]byte("Hello world!"))

			if err != nil {
				logf("netstack writer: could not write message")
			}
		}()

		for {
			buf := make([]byte, 1500)
			logf("netstack: about to read")
			n, err := conn.Read(buf)
			logf("netstack: did read")
			if err != nil {
				logf("nestack: cannot read further, exiting with message %v", err)
				break
			} else {
				logf("netstack: received data: % x", buf[:n])
			}
		}

		<-writerCompletedCh

		conn.Close()
	}

	requestSent := false
	readyToSendRequest := make(chan struct{})

	e.AddNetworkMapCallback(func(nm *netmap.NetworkMap) {
		oldIPs := make(map[tcpip.Address]bool)
		for _, ip := range ipstack.AllAddresses()[nicID] {
			oldIPs[ip.AddressWithPrefix.Address] = true
		}
		newIPs := make(map[tcpip.Address]bool)
		for _, ip := range nm.Addresses {
			// no IPv6 rn
			if ip.IP.Is4() {
				newIPs[tcpip.Address(ip.IPNet().IP)] = true
			}
		}

		ipsToBeAdded := make(map[tcpip.Address]bool)
		for ip := range newIPs {
			if !oldIPs[ip] {
				ipsToBeAdded[ip] = true
			}
		}
		ipsToBeRemoved := make(map[tcpip.Address]bool)
		for ip := range oldIPs {
			if !newIPs[ip] {
				ipsToBeRemoved[ip] = true
			}
		}

		for ip := range ipsToBeRemoved {
			err := ipstack.RemoveAddress(nicID, ip)
			if err != nil {
				logf("netstack: could not deregister IP %s: %v", ip, err)
			} else {
				logf("netstack: deregistered IP %s", ip)
			}
		}
		for ip := range ipsToBeAdded {
			err := ipstack.AddAddress(nicID, ipv4.ProtocolNumber, ip)
			if err != nil {
				logf("netstack: could not register IP %s: %v", ip, err)
			} else {
				logf("netstack: registered IP %s", ip)
			}
		}

		if !requestSent {
			go func() {
				<-readyToSendRequest
				sendRequest()
			}()
			requestSent = true
		}
	})

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

	udpFwd := udp.NewForwarder(ipstack, func(r *udp.ForwarderRequest) {
		logf("XXX UDP ForwarderRequest: %v", r)
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			logf("Could not create endpoint, exiting")
			return
		}
		c := gonet.NewUDPConn(ipstack, &wq, ep)
		go func() {
			//fmt.Fprintf(c, "Hi, %s! Echoing, hopefully...", c.RemoteAddr())
			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf)
				if err != nil {
					logf("netstack UDP fin: %v", err)
					break
				}
				c.Write(buf[:n])
			}
			c.Close()
		}()
	})

	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

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

	close(readyToSendRequest)

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
