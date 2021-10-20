// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows && !darwin && !js
// +build !linux,!windows,!darwin,!js

package portlist

import "time"

// We have to run netstat, which is a bit expensive, so don't do it too often.
const pollInterval = 5 * time.Second

func listPorts() (List, error) {
	return listPortsNetstat("-na")
}

func addProcesses(pl []Port) ([]Port, error) {
	// Generic version has no way to get process mappings.
	// This has to be OS-specific.
	return pl, nil
}
