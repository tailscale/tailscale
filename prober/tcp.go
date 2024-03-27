// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"fmt"
	"net"
)

// TCP returns a Probe that healthchecks a TCP endpoint.
//
// The ProbeFunc reports whether it can successfully connect to addr.
func TCP(addr string) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeTCP(ctx, addr)
		},
		Class: "tcp",
	}
}

func probeTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dialing %q: %v", addr, err)
	}
	conn.Close()
	return nil
}
