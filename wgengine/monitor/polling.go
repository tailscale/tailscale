// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//  +build !freebsd,!windows,!darwin

package monitor

import (
	"errors"
	"runtime"
	"sync"
	"time"

	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

func newPollingMon(logf logger.Logf, m *Mon) (osMon, error) {
	return &pollingMon{
		logf: logf,
		m:    m,
		stop: make(chan struct{}),
	}, nil
}

// pollingMon is a bad but portable implementation of the link monitor
// that works by polling the interface state every 10 seconds, in lieu
// of anything to subscribe to.
type pollingMon struct {
	logf logger.Logf
	m    *Mon

	closeOnce sync.Once
	stop      chan struct{}
}

func (pm *pollingMon) Close() error {
	pm.closeOnce.Do(func() {
		close(pm.stop)
	})
	return nil
}

func (pm *pollingMon) Receive() (message, error) {
	d := 10 * time.Second
	if runtime.GOOS == "android" {
		// We'll have Android notify the link monitor to wake up earlier,
		// so this can go very slowly there, to save battery.
		// https://github.com/tailscale/tailscale/issues/1427
		d = 10 * time.Minute
	}
	// TODO: detect if we're running in Cloud Run, and reduce frequency of
	// polling as its routes never change.
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	base := pm.m.InterfaceState()
	for {
		if cur, err := pm.m.interfaceStateUncached(); err == nil && !cur.EqualFiltered(base, interfaces.FilterInteresting) {
			return unspecifiedMessage{}, nil
		}
		select {
		case <-ticker.C:
		case <-pm.stop:
			return nil, errors.New("stopped")
		}
	}
}
