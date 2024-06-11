// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"context"
	"net"

	"github.com/akutz/memconn"
)

const memName = "Tailscale-IPN"

func listen(path string) (net.Listener, error) {
	return memconn.Listen("memu", memName)
}

func connect(ctx context.Context, _ string) (net.Conn, error) {
	return memconn.DialContext(ctx, "memu", memName)
}
