// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"bufio"
	"context"
	"net"

	"tailscale.com/types/logger"
)

func (s *Server) handleProxyConnectConn(ctx context.Context, br *bufio.Reader, c net.Conn, logf logger.Logf) {
	panic("unreachable")
}
