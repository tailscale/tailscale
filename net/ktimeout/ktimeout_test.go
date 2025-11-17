// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"context"
	"fmt"
	"net"
	"time"
)

func ExampleUserTimeout() {
	lc := net.ListenConfig{
		Control: UserTimeout(30 * time.Second),
	}
	ln, err := lc.Listen(context.TODO(), "tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("error: %v", err)
		return
	}
	ln.Close()
	// Output:
}
