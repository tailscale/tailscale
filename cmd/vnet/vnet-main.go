// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The vnet binary runs a virtual network stack in userspace for qemu instances
// to connect to and simulate various network conditions.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"tailscale.com/tstest/natlab/vnet"
)

var (
	listen  = flag.String("listen", "/tmp/qemu.sock", "path to listen on")
	nat     = flag.String("nat", "easy", "type of NAT to use")
	portmap = flag.Bool("portmap", false, "enable portmapping")
	dgram   = flag.Bool("dgram", false, "enable datagram mode; for use with macOS Hypervisor.Framework and VZFileHandleNetworkDeviceAttachment")
)

func main() {
	flag.Parse()

	if _, err := os.Stat(*listen); err == nil {
		os.Remove(*listen)
	}

	var srv net.Listener
	var err error
	var conn *net.UnixConn
	if *dgram {
		addr, err := net.ResolveUnixAddr("unixgram", *listen)
		if err != nil {
			log.Fatalf("ResolveUnixAddr: %v", err)
		}
		conn, err = net.ListenUnixgram("unixgram", addr)
		if err != nil {
			log.Fatalf("ListenUnixgram: %v", err)
		}
		defer conn.Close()
	} else {
		srv, err = net.Listen("unix", *listen)
	}
	if err != nil {
		log.Fatal(err)
	}

	var c vnet.Config
	node1 := c.AddNode(c.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.NAT(*nat)))
	c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", vnet.NAT(*nat)))
	if *portmap {
		node1.Network().AddService(vnet.NATPMP)
	}

	s, err := vnet.New(&c)
	if err != nil {
		log.Fatalf("newServer: %v", err)
	}

	if err := s.PopulateDERPMapIPs(); err != nil {
		log.Printf("warning: ignoring failure to populate DERP map: %v", err)
	}

	s.WriteStartingBanner(os.Stdout)

	go func() {
		getStatus := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			st, err := s.NodeStatus(ctx, node1)
			if err != nil {
				log.Printf("NodeStatus: %v", err)
				return
			}
			log.Printf("NodeStatus: %q", st)
		}
		for {
			time.Sleep(5 * time.Second)
			getStatus()
		}
	}()

	if conn != nil {
		s.ServeUnixConn(conn, vnet.ProtocolUnixDGRAM)
		return
	}

	for {
		c, err := srv.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go s.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
	}
}
