// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

// Command udp_tester exists because all of these distros being tested don't
// have a consistent tool for doing UDP traffic. This is a very hacked up tool
// that does that UDP traffic so these tests can be done.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
)

var (
	client = flag.String("client", "", "host:port to connect to for sending UDP")
	server = flag.String("server", "", "host:port to bind to for receiving UDP")
)

func main() {
	flag.Parse()

	if *client == "" && *server == "" {
		log.Fatal("specify -client or -server")
	}

	if *client != "" {
		conn, err := net.Dial("udp", *client)
		if err != nil {
			log.Fatalf("can't dial %s: %v", *client, err)
		}
		log.Printf("dialed to %s", conn.RemoteAddr())
		defer conn.Close()

		buf := make([]byte, 2048)
		n, err := os.Stdin.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatalf("can't read from stdin: %v", err)
		}

		nn, err := conn.Write(buf[:n])
		if err != nil {
			log.Fatalf("can't write to %s: %v", conn.RemoteAddr(), err)
		}

		if n == nn {
			return
		}

		log.Fatalf("wanted to write %d bytes, wrote %d bytes", n, nn)
	}

	if *server != "" {
		addr, err := net.ResolveUDPAddr("udp", *server)
		if err != nil {
			log.Fatalf("can't resolve %s: %v", *server, err)
		}
		ln, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalf("can't listen %s: %v", *server, err)
		}
		defer ln.Close()

		buf := make([]byte, 2048)

		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}

		os.Stdout.Write(buf[:n])
	}
}
