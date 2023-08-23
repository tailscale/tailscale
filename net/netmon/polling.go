// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !darwin

package netmon

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

func newPollingMon(logf logger.Logf, m *Monitor) (osMon, error) {
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
	m    *Monitor

	closeOnce sync.Once
	stop      chan struct{}
}

func (pm *pollingMon) IsInterestingInterface(iface string) bool {
	return true
}

func (pm *pollingMon) Close() error {
	pm.closeOnce.Do(func() {
		close(pm.stop)
	})
	return nil
}

func (pm *pollingMon) isCloudRun() bool {
	// https: //cloud.google.com/run/docs/reference/container-contract#env-vars
	if os.Getenv("K_REVISION") == "" || os.Getenv("K_CONFIGURATION") == "" ||
		os.Getenv("K_SERVICE") == "" || os.Getenv("PORT") == "" {
		return false
	}
	vers, err := os.ReadFile("/proc/version")
	if err != nil {
		pm.logf("Failed to read /proc/version: %v", err)
		return false
	}
	return string(bytes.TrimSpace(vers)) == "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"
}

func (pm *pollingMon) Receive() (message, error) {
	d := 10 * time.Second
	if runtime.GOOS == "android" {
		// We'll have Android notify the link monitor to wake up earlier,
		// so this can go very slowly there, to save battery.
		// https://github.com/tailscale/tailscale/issues/1427
		d = 10 * time.Minute
	} else if pm.isCloudRun() {
		// Cloud Run routes never change at runtime. the containers are killed within
		// 15 minutes by default, set the interval long enough to be effectively infinite.
		pm.logf("monitor polling: Cloud Run detected, reduce polling interval to 24h")
		d = 24 * time.Hour
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return unspecifiedMessage{}, nil
		case <-pm.stop:
			return nil, errors.New("stopped")
		}
	}
}
