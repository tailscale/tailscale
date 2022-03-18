// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"context"
	"fmt"
	"net"
)

// TCP returns a Probe that healthchecks a TCP endpoint.
//
// The Probe reports whether it can successfully connect to addr.
func TCP(addr string) Probe {
	return func(ctx context.Context) error {
		return probeTCP(ctx, addr)
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
