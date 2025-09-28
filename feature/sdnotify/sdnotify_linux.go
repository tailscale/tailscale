// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package sdnotify

import (
	"errors"
	"log"
	"os"
	"sync"

	"github.com/mdlayher/sdnotify"
	"tailscale.com/feature"
)

func init() {
	feature.HookSystemdReady.Set(ready)
	feature.HookSystemdStatus.Set(status)
}

var getNotifyOnce struct {
	sync.Once
	v *sdnotify.Notifier
}

type logOnce struct {
	sync.Once
}

func (l *logOnce) logf(format string, args ...any) {
	l.Once.Do(func() {
		log.Printf(format, args...)
	})
}

var (
	readyOnce  = &logOnce{}
	statusOnce = &logOnce{}
)

func notifier() *sdnotify.Notifier {
	getNotifyOnce.Do(func() {
		var err error
		getNotifyOnce.v, err = sdnotify.New()
		// Not exist means probably not running under systemd, so don't log.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("systemd: systemd-notifier error: %v", err)
		}
	})
	return getNotifyOnce.v
}

// ready signals readiness to systemd. This will unblock service dependents from starting.
func ready() {
	err := notifier().Notify(sdnotify.Ready)
	if err != nil {
		readyOnce.logf("systemd: error notifying: %v", err)
	}
}

// status sends a single line status update to systemd so that information shows up
// in systemctl output. For example:
//
//	$ systemctl status tailscale
//	● tailscale.service - Tailscale client daemon
//	Loaded: loaded (/nix/store/qc312qcy907wz80fqrgbbm8a9djafmlg-unit-tailscale.service/tailscale.service; enabled; vendor preset: enabled)
//	Active: active (running) since Tue 2020-11-24 17:54:07 EST; 13h ago
//	Main PID: 26741 (.tailscaled-wra)
//	Status: "Connected; user@host.domain.tld; 100.101.102.103"
//	IP: 0B in, 0B out
//	Tasks: 22 (limit: 4915)
//	Memory: 30.9M
//	CPU: 2min 38.469s
//	CGroup: /system.slice/tailscale.service
//	└─26741 /nix/store/sv6cj4mw2jajm9xkbwj07k29dj30lh0n-tailscale-date.20200727/bin/tailscaled --port 41641
func status(format string, args ...any) {
	err := notifier().Notify(sdnotify.Statusf(format, args...))
	if err != nil {
		statusOnce.logf("systemd: error notifying: %v", err)
	}
}
