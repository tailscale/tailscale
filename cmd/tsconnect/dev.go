// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"log"
)

func runDev() {
	buildOptions, err := commonSetup(devMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}
	runEsbuildServe(*buildOptions)
}
