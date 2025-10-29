// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// Command dns_tester exists in order to perform tests of our DNS
// configuration stack. This was written because the state of DNS
// in our target environments is so diverse that we need a little tool
// to do this test for us.
package main

import (
	"context"
	jsonv1 "encoding/json"
	"flag"
	"net"
	"os"
	"time"
)

func main() {
	flag.Parse()
	target := flag.Arg(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCount := 0
	wait := 25 * time.Millisecond
	for range make([]struct{}, 5) {
		err := lookup(ctx, target)
		if err != nil {
			errCount++
			time.Sleep(wait)
			wait = wait * 2
			continue
		}

		break
	}
}

func lookup(ctx context.Context, target string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	hosts, err := net.LookupHost(target)
	if err != nil {
		return err
	}

	jsonv1.NewEncoder(os.Stdout).Encode(hosts)
	return nil
}
