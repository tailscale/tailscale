// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import (
	"errors"
	"io"
	"net"
	"time"
)

func getConnKernelTimestamp() (io.ReadWriteCloser, error) {
	return nil, errors.New("unimplemented")
}

func measureRTTKernel(conn io.ReadWriteCloser, dst *net.UDPAddr) (rtt time.Duration, err error) {
	return 0, errors.New("unimplemented")
}

func supportsKernelTS() bool {
	return false
}
