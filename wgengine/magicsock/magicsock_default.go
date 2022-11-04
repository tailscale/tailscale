// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package magicsock

import (
	"errors"
	"io"

	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	return nil, errors.New("raw disco listening not supported on this OS")
}

func trySetSocketBuffer(pconn nettype.PacketConn, logf logger.Logf) {
	portableTrySetSocketBuffer(pconn, logf)
}
