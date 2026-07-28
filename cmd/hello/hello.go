// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The hello binary runs hello.ts.net.
package main // import "tailscale.com/cmd/hello"

import (
	"log"

	"tailscale.com/cmd/hello/helloserver"
)

func main() {
	s := &helloserver.Server{
		HTTPAddr:  ":80",
		HTTPSAddr: ":443",
	}
	log.Printf("Starting hello server.")
	log.Fatal(s.Run())
}
