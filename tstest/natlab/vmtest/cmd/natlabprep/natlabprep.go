// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The natlabprep tool warms the local natlab vmtest cache by downloading
// every cloud VM image natlab can boot and, with --gokrazy, building every
// gokrazy image. It is intended for CI prep steps so a subsequent test run
// does not pay the per-image download or build cost.
package main

import (
	"context"
	"flag"
	"log"

	"tailscale.com/tstest/natlab/vmtest"
)

var gokrazy = flag.Bool("gokrazy", false, "also build the gokrazy images (requires make and qemu-img)")

func main() {
	flag.Parse()
	ctx := context.Background()
	for _, img := range vmtest.CloudImages() {
		log.Printf("ensuring %s ...", img.Name)
		if err := vmtest.EnsureImage(ctx, img); err != nil {
			log.Fatalf("ensuring %s: %v", img.Name, err)
		}
	}
	if *gokrazy {
		for _, img := range vmtest.GokrazyImages() {
			if err := vmtest.BuildGokrazyImage(ctx, img); err != nil {
				log.Fatalf("building %s: %v", img.Name, err)
			}
		}
	}
}
