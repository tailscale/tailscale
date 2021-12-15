// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logpolicy

import (
	"io"
	"log"

	"golang.org/x/sys/windows/svc"
	"tailscale.com/log/filelogger"
)

func maybeWrapForPlatform(lw io.Writer, cmdName, logID string) io.Writer {
	if cmdName != "tailscaled" {
		return lw
	}

	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return lw
	}

	return filelogger.New("tailscale-service", logID, log.New(lw, "", 0))
}
