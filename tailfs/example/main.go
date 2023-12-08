// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package main gives an example of running a webdav server that delegates to
// two other webdav servers. This is analogous to a Tailscale node that has
// access to two Tailscale nodes that are sharing some folders with TailFS,
// except that it's all happening on the same machine and not intermediated by
// Tailscale.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"tailscale.com/tailfs"
)

func main() {
	dir1 := os.Args[1]
	dir2 := os.Args[2]

	server1, server1Addr, err := tailfs.ListenAndServe("127.0.0.1:", nil)
	if err != nil {
		log.Fatal(err)
	}
	server1.AddShare("myshare", dir1)

	server2, server2Addr, err := tailfs.ListenAndServe("127.0.0.1:", nil)
	if err != nil {
		log.Fatal(err)
	}
	server2.AddShare("myshare", dir2)

	local, localAddr, err := tailfs.ListenAndServe("127.0.0.1:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
	local.SetRemotes("tailnetdomain", map[string]string{
		"server1": fmt.Sprintf("http://%v", server1Addr),
		"server2": fmt.Sprintf("http://%v", server2Addr),
	}, nil)

	log.Printf("WebDAV server at %v\n", localAddr)
	time.Sleep(5 * time.Hour)
}
