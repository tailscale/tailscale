// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command stunc makes a STUN request to a STUN server and prints the result.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"tailscale.com/net/stun"
)

func main() {
	log.SetFlags(0)
	var host string
	port := "3478"

	var readTimeout time.Duration
	flag.DurationVar(&readTimeout, "timeout", 3*time.Second, "response wait timeout")

	flag.Parse()

	values := flag.Args()
	if len(values) < 1 || len(values) > 2 {
		log.Printf("usage: %s <hostname> [port]", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	} else {
		for i, value := range values {
			switch i {
			case 0:
				host = value
			case 1:
				port = value
			}
		}
	}
	_, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		log.Fatalf("invalid port: %v", err)
	}

	uaddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatal(err)
	}
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatal(err)
	}

	txID := stun.NewTxID()
	req := stun.Request(txID)

	_, err = c.WriteToUDP(req, uaddr)
	if err != nil {
		log.Fatal(err)
	}

	err = c.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		log.Fatal(err)
	}
	var buf [1024]byte
	n, raddr, err := c.ReadFromUDPAddrPort(buf[:])
	if err != nil {
		log.Fatal(err)
	}

	tid, saddr, err := stun.ParseResponse(buf[:n])
	if err != nil {
		log.Fatal(err)
	}
	if tid != txID {
		log.Fatalf("txid mismatch: got %v, want %v", tid, txID)
	}

	log.Printf("sent addr: %v", uaddr)
	log.Printf("from addr: %v", raddr)
	log.Printf("stun addr: %v", saddr)
}
