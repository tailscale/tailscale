// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command stunc makes a STUN request to a STUN server and prints the result.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"tailscale.com/net/stun"
)

var (
	rate    = flag.Duration("rate", time.Second, "rate at which to send probes (0 means as fast as possible)")
	timeout = flag.Duration("timeout", time.Second, "time to wait for a response")
	reuse   = flag.Bool("reuse", true, "reuse the same UDP socket for each probe")
	jsonout = flag.Bool("json", false, "output in JSON format (default is human-readable)")
)

func main() {
	flag.Usage = func() {
		fmt.Printf("usage: %s [flags] <hostname>", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	host := flag.Args()[0]

	naddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		log.Fatal(err)
	}

	nip, err := netip.ParseAddr(naddr.String())
	if err != nil {
		log.Fatal(err)
	}

	uaddr := netip.AddrPortFrom(nip, 3478)

	var c *net.UDPConn

	var print = func(result map[string]string) {
		r := result["status"]
		if result["status"] == "ok" {
			r = fmt.Sprintf("%s; %s < %s in %s", result["status"], result["from"], result["stun"], result["dur"])
		}
		fmt.Printf("%s > %s; %s\n", result["local"], result["to"], r)
	}
	if *jsonout {
		j := json.NewEncoder(os.Stdout)
		print = func(result map[string]string) {
			if err := j.Encode(result); err != nil {
				log.Fatal(err)
			}
		}
	}

	for {
		if c == nil || !*reuse {
			if c != nil {
				c.Close()
			}

			c, err = net.ListenUDP("udp", nil)
			if err != nil {
				log.Fatal(err)
			}
		}

		result := map[string]string{}
		result["to"] = uaddr.String()
		result["local"] = c.LocalAddr().String()

		txID := stun.NewTxID()
		req := stun.Request(txID)

		t0 := time.Now()
		result["at"] = t0.Format(time.RFC3339Nano)
		_, err = c.WriteToUDPAddrPort(req, uaddr)
		if err != nil {
			log.Fatal(err)
		}

		c.SetReadDeadline(t0.Add(*timeout))
		var buf [1024]byte
		n, raddr, err := c.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				result["status"] = "timeout"
				print(result)
				continue
			}
			log.Fatalf("%#v", err)
		}
		result["from"] = raddr.String()
		result["dur"] = time.Since(t0).String()

		tid, saddr, err := stun.ParseResponse(buf[:n])
		if err != nil {
			log.Fatal(err)
		}
		result["stun"] = saddr.String()
		if tid != txID {
			result["status"] = "badtxid"
		} else {
			result["status"] = "ok"
		}

		print(result)
		time.Sleep(time.Until(t0.Add(*rate)))
	}
}
