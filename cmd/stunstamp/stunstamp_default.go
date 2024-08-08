// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import (
	"errors"
	"io"
	"net/netip"
	"time"
)

func getUDPConnKernelTimestamp() (io.ReadWriteCloser, error) {
	return nil, errors.New("unimplemented")
}

func measureSTUNRTTKernel(conn io.ReadWriteCloser, dst netip.AddrPort) (rtt time.Duration, err error) {
	return 0, errors.New("unimplemented")
}

func protocolSupportsKernelTS(_ protocol) bool {
	return false
}
