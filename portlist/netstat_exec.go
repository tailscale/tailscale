// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows freebsd openbsd darwin,amd64

package portlist

import (
	"fmt"
	"strings"

	exec "tailscale.com/tempfork/osexec"
)

func listPortsNetstat(arg string) (List, error) {
	exe, err := exec.LookPath("netstat")
	if err != nil {
		return nil, fmt.Errorf("netstat: lookup: %v", err)
	}
	output, err := exec.Command(exe, arg).Output()
	if err != nil {
		xe, ok := err.(*exec.ExitError)
		stderr := ""
		if ok {
			stderr = strings.TrimSpace(string(xe.Stderr))
		}
		return nil, fmt.Errorf("netstat: %v (%q)", err, stderr)
	}

	return parsePortsNetstat(string(output)), nil
}
