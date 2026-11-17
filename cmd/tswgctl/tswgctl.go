// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// The tswgctl command is a debugging tool, in the spirit of wg(8), that
// configures and inspects tswg kernel devices.
//
// Usage:
//
//	tswgctl genkey
//	tswgctl pubkey privkey:...
//	tswgctl set IFNAME [-private-key=privkey:...] [-listen-port=N]
//	        [-peer=nodekey:... [-endpoint=IP:PORT] [-allowed-ips=PREFIX,...]
//	        [-keepalive=DURATION] [-remove]]
//	tswgctl show IFNAME
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "genkey":
		b, _ := key.NewNode().MarshalText()
		fmt.Println(string(b))
	case "pubkey":
		if len(os.Args) != 3 {
			usage()
		}
		var k key.NodePrivate
		if err := k.UnmarshalText([]byte(os.Args[2])); err != nil {
			log.Fatal(err)
		}
		fmt.Println(k.Public().String())
	case "set":
		set(os.Args[2:])
	case "show":
		if len(os.Args) != 3 {
			usage()
		}
		show(os.Args[2])
	default:
		usage()
	}
}

func usage() {
	log.Fatal("usage: tswgctl {genkey | pubkey PRIVKEY | set IFNAME [flags] | show IFNAME}")
}

func set(args []string) {
	if len(args) < 1 {
		usage()
	}
	ifname := args[0]
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	privKey := fs.String("private-key", "", "device private key (privkey:...)")
	listenPort := fs.Int("listen-port", -1, "UDP listen port; 0 for random; -1 for unchanged")
	peer := fs.String("peer", "", "peer public key (nodekey:...)")
	endpoint := fs.String("endpoint", "", "peer endpoint IP:PORT")
	allowedIPs := fs.String("allowed-ips", "", "comma-separated peer allowed IP prefixes")
	keepalive := fs.Duration("keepalive", -1, "peer persistent keepalive interval; 0 disables; negative for unchanged")
	remove := fs.Bool("remove", false, "remove the peer")
	fs.Parse(args[1:])

	var cfg tswg.Config
	if *privKey != "" {
		var k key.NodePrivate
		if err := k.UnmarshalText([]byte(*privKey)); err != nil {
			log.Fatalf("-private-key: %v", err)
		}
		cfg.PrivateKey = &k
	}
	if *listenPort >= 0 {
		p := uint16(*listenPort)
		cfg.ListenPort = &p
	}
	if *peer != "" {
		var pc tswg.PeerConfig
		if err := pc.PublicKey.UnmarshalText([]byte(*peer)); err != nil {
			log.Fatalf("-peer: %v", err)
		}
		pc.Remove = *remove
		if *endpoint != "" {
			ap, err := netip.ParseAddrPort(*endpoint)
			if err != nil {
				log.Fatalf("-endpoint: %v", err)
			}
			pc.Endpoint = ap
		}
		if *allowedIPs != "" {
			for s := range strings.SplitSeq(*allowedIPs, ",") {
				pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					log.Fatalf("-allowed-ips: %v", err)
				}
				pc.AllowedIPs = append(pc.AllowedIPs, pfx)
			}
		}
		if *keepalive >= 0 {
			d := time.Duration(*keepalive)
			pc.PersistentKeepalive = &d
		}
		cfg.Peers = append(cfg.Peers, pc)
	}

	c, err := tswg.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	if err := c.ConfigureDevice(ifname, cfg); err != nil {
		log.Fatal(err)
	}
}

func show(ifname string) {
	c, err := tswg.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	d, err := c.Device(ifname)
	if err != nil {
		log.Fatal(err)
	}
	d.PrivateKey = key.NodePrivate{} // don't print secrets
	j, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(j))
}
