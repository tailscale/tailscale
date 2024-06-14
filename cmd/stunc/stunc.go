// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command stunc makes a STUN request to a STUN server and prints the result.
package main

import (
	"log"
	"net"
	"os"
	"strconv"

	"tailscale.com/net/stun"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 || len(os.Args) > 3 {
		log.Fatalf("usage: %s <hostname> [port]", os.Args[0])
	}
	host := os.Args[1]
	port := "3478"
	if len(os.Args) == 3 {
		port = os.Args[2]
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
