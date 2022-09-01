// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"net"
	"strconv"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

func runDev() {
	buildOptions, err := commonSetup(devMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}
	host, portStr, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("Cannot parse addr: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		log.Fatalf("Cannot parse port: %v", err)
	}
	result, err := esbuild.Serve(esbuild.ServeOptions{
		Port:     uint16(port),
		Host:     host,
		Servedir: "./",
	}, *buildOptions)
	if err != nil {
		log.Fatalf("Cannot start esbuild server: %v", err)
	}
	log.Printf("Listening on http://%s:%d\n", result.Host, result.Port)
	result.Wait()
}
