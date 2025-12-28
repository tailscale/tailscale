// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command distsign tests downloads and signature validating for packages
// published by Tailscale on pkgs.tailscale.com.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"

	"tailscale.com/clientupdate/distsign"
)

var (
	pkgsURL = flag.String("pkgs-url", "https://pkgs.tailscale.com/", "URL of the packages server")
	pkgName = flag.String("pkg-name", "", "name of the package on the packages server, including the stable/unstable track prefix")
)

func main() {
	flag.Parse()

	if *pkgName == "" {
		log.Fatalf("--pkg-name is required")
	}

	c, err := distsign.NewClient(log.Printf, *pkgsURL)
	if err != nil {
		log.Fatal(err)
	}
	tempDir := filepath.Join(os.TempDir(), "distsign")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Fatal(err)
	}
	if err := c.Download(context.Background(), *pkgName, filepath.Join(os.TempDir(), "distsign", filepath.Base(*pkgName))); err != nil {
		log.Fatal(err)
	}
	log.Printf("%q ok", *pkgName)
}
