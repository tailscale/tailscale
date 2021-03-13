// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func init() {
	osVersion = osVersionWindows
}

func osVersionWindows() string {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}
