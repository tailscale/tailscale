// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
)

func runDevPkg() {
	buildOptions, err := commonPkgSetup(devMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}
	runEsbuildServe(*buildOptions)
}
