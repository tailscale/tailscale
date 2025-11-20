// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !wasm && !tamago && !aix && !solaris && !illumos

// Package tun creates a tuntap device, working around OS-specific
// quirks if necessary.
package tstun

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/types/logger"
)

// CreateTAP is the hook maybe set by feature/tap.
var CreateTAP feature.Hook[func(logf logger.Logf, tapName, bridgeName string) (tun.Device, error)]

// HookSetLinkAttrs is the hook maybe set by feature/linkspeed.
var HookSetLinkAttrs feature.Hook[func(tun.Device) error]

// modprobeTunHook is a Linux-specific hook to run "/sbin/modprobe tun".
var modprobeTunHook feature.Hook[func() error]

// New returns a tun.Device for the requested device name, along with
// the OS-dependent name that was allocated to the device.
func New(logf logger.Logf, tunName string) (tun.Device, string, error) {
	var dev tun.Device
	var err error
	if strings.HasPrefix(tunName, "tap:") {
		if runtime.GOOS != "linux" {
			return nil, "", errors.New("tap only works on Linux")
		}
		if !CreateTAP.IsSet() { // if the ts_omit_tap tag is used
			return nil, "", errors.New("tap is not supported in this build")
		}
		f := strings.Split(tunName, ":")
		var tapName, bridgeName string
		switch len(f) {
		case 2:
			tapName = f[1]
		case 3:
			tapName, bridgeName = f[1], f[2]
		default:
			return nil, "", errors.New("bogus tap argument")
		}
		dev, err = CreateTAP.Get()(logf, tapName, bridgeName)
	} else {
		if runtime.GOOS == "plan9" {
			cleanUpPlan9Interfaces()
		}
		// Try to create the TUN device up to two times. If it fails
		// the first time and we're on Linux, try a desperate
		// "modprobe tun" to load the tun module and try again.
		for try := range 2 {
			dev, err = tun.CreateTUN(tunName, int(DefaultTUNMTU()))
			if err == nil || !modprobeTunHook.IsSet() {
				if try > 0 {
					logf("created TUN device %q after doing `modprobe tun`", tunName)
				}
				break
			}
			if modprobeTunHook.Get()() != nil {
				// modprobe failed; no point trying again.
				break
			}
		}
	}
	if err != nil {
		return nil, "", err
	}
	if err := waitInterfaceUp(dev, 90*time.Second, logf); err != nil {
		dev.Close()
		return nil, "", err
	}
	if buildfeatures.HasLinkSpeed {
		if f, ok := HookSetLinkAttrs.GetOk(); ok {
			if err := f(dev); err != nil {
				logf("setting link attributes: %v", err)
			}
		}
	}
	name, err := interfaceName(dev)
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	return dev, name, nil
}

func cleanUpPlan9Interfaces() {
	maybeUnbind := func(n int) {
		b, err := os.ReadFile(fmt.Sprintf("/net/ipifc/%d/status", n))
		if err != nil {
			return
		}
		status := string(b)
		if !(strings.HasPrefix(status, "device  maxtu ") ||
			strings.Contains(status, "fd7a:115c:a1e0:")) {
			return
		}
		f, err := os.OpenFile(fmt.Sprintf("/net/ipifc/%d/ctl", n), os.O_RDWR, 0)
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := fmt.Fprintf(f, "unbind\n"); err != nil {
			log.Printf("unbind interface %v: %v", n, err)
			return
		}
		log.Printf("tun: unbound stale interface %v", n)
	}

	// A common case: after unclean shutdown we might leave interfaces
	// behind. Look for our straggler(s) and clean them up.
	for n := 2; n < 5; n++ {
		maybeUnbind(n)
	}
}

// tunDiagnoseFailure, if non-nil, does OS-specific diagnostics of why
// TUN failed to work.
var tunDiagnoseFailure func(tunName string, logf logger.Logf, err error)

// Diagnose tries to explain a tuntap device creation failure.
// It pokes around the system and logs some diagnostic info that might
// help debug why tun creation failed. Because device creation has
// already failed and the program's about to end, log a lot.
//
// The tunName is the name of the tun device that was requested but failed.
// The err error is how the tun creation failed.
func Diagnose(logf logger.Logf, tunName string, err error) {
	if tunDiagnoseFailure != nil {
		tunDiagnoseFailure(tunName, logf, err)
	} else {
		logf("no TUN failure diagnostics for OS %q", runtime.GOOS)
	}
}
