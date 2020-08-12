// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!freebsd,!windows android

package monitor

import "tailscale.com/types/logger"

func newOSMon(logger.Logf) (osMon, error) { return nil, nil }
