// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command stunc makes a STUN request to a STUN server and prints the result.
package main

import (
	"log"
	"net"
	"os"

	"tailscale.com/net/stun"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <hostname>", os.Args[0])
	}
	host := os.Args[1]

	uaddr, err := net.ResolveUDPAddr("udp", host+":3478")
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
