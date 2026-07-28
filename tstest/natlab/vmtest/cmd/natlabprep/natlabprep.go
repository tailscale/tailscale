// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The natlabprep tool warms the local natlab vmtest cache by downloading
// every cloud VM image natlab can boot. It is intended for CI prep steps
// so a subsequent test run does not pay the per-image download cost.
package main

import (
	"context"
	"log"

	"tailscale.com/tstest/natlab/vmtest"
)

func main() {
	ctx := context.Background()
	for _, img := range vmtest.CloudImages() {
		log.Printf("ensuring %s ...", img.Name)
		if err := vmtest.EnsureImage(ctx, img); err != nil {
			log.Fatalf("ensuring %s: %v", img.Name, err)
		}
	}
}
