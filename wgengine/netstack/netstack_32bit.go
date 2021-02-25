// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netstack doesn't build on 32-bit machines (https://github.com/google/gvisor/issues/5241)
// +build !amd64,!arm64,!ppc64le,!riscv64,!s390x

package netstack

import (
	"errors"

	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/tstun"
)

func Create(logf logger.Logf, tundev *tstun.TUN, e wgengine.Engine, mc *magicsock.Conn) (wgengine.FakeImpl, error) {
	return nil, errors.New("netstack is not supported on 32-bit platforms for now; see https://github.com/google/gvisor/issues/5241")
}
