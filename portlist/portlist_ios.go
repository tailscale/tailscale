// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,!amd64

package portlist

import (
	"errors"
	"time"
)

const pollInterval = 9999 * time.Hour

func listPorts() (List, error) {
	return nil, errors.New("not implemented")
}

func addProcesses(pl []Port) ([]Port, error) {
	return nil, errors.New("not implemented")
}
