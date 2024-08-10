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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

var (
	listen  = flag.String("listen", "/tmp/qemu.sock", "path to listen on")
	nat     = flag.String("nat", "easy", "type of NAT to use")
	nat2    = flag.String("nat2", "hard", "type of NAT to use for second network")
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
	c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", vnet.NAT(*nat2)))
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
	nc := s.NodeAgentClient(node1)
	go func() {
		rp := httputil.NewSingleHostReverseProxy(must.Get(url.Parse("http://gokrazy")))
		d := rp.Director
		rp.Director = func(r *http.Request) {
			d(r)
			r.Header.Set("X-TTA-GoKrazy", "1")
		}
		rp.Transport = nc.HTTPClient.Transport
		http.ListenAndServe(":8080", rp)
	}()
	go func() {
		getStatus := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			st, err := nc.Status(ctx)
			if err != nil {
				log.Printf("NodeStatus: %v", err)
				return
			}
			log.Printf("NodeStatus: %v", logger.AsJSON(st))
		}
		for {
			time.Sleep(5 * time.Second)
			//continue
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
