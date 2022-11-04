// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
