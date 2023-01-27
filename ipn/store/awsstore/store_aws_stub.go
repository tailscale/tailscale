// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_aws

package awsstore

import (
	"fmt"
	"runtime"

	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

func New(logger.Logf, string) (ipn.StateStore, error) {
	return nil, fmt.Errorf("AWS store is not supported on %v", runtime.GOOS)
}
