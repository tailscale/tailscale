// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import "time"

const pollInterval = 365 * 24 * time.Hour

func appendListeningPorts(base []Port) ([]Port, error) {
	return base, nil
}

func addProcesses(pl []Port) ([]Port, error) {
	return pl, nil
}
