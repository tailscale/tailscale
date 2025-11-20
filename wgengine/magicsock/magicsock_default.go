// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_listenrawdisco

package magicsock

import (
	"errors"
	"fmt"
	"io"
)

func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	return nil, fmt.Errorf("raw disco listening not supported on this OS: %w", errors.ErrUnsupported)
}
