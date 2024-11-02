// The lopower server is a "Little Opinionated Proxy Over
// Wireguard-Encrypted Route". It bridges a static WireGuard
// client into a Tailscale network.
package main

import (
	"flag"
	"log"
	"os"

	"tailscale.com/tsnet"
)

func main() {
	flag.Parse()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	ts := &tsnet.Server{
		Hostname:  hostname,
		UserLogf:  log.Printf,
		Ephemeral: false,
	}

	if err := ts.Start(); err != nil {
		log.Fatal(err)
	}

	select {}
}
