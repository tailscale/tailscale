// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

// Forking on Windows is insanely expensive, so don't do it too often.
const POLL_SECONDS = 5

func listPorts() (List, error) {
	return listPortsNetstat("-na")
}

func addProcesses(pl []Port) ([]Port, error) {
	return listPortsNetstat("-nab")
}
