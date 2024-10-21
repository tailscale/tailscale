// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !wasm && !plan9 && !tamago && !aix

// Package tun creates a tuntap device, working around OS-specific
// quirks if necessary.
package tstun

import (
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// createTAP is non-nil on Linux.
var createTAP func(logf logger.Logf, tapName, bridgeName string) (tun.Device, error)

// New returns a tun.Device for the requested device name, along with
// the OS-dependent name that was allocated to the device.
func New(logf logger.Logf, tunName string) (tun.Device, string, error) {
	var dev tun.Device
	var err error
	if strings.HasPrefix(tunName, "tap:") {
		if runtime.GOOS != "linux" {
			return nil, "", errors.New("tap only works on Linux")
		}
		if createTAP == nil { // if the ts_omit_tap tag is used
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
		dev, err = createTAP(logf, tapName, bridgeName)
	} else {
		dev, err = tun.CreateTUN(tunName, int(DefaultTUNMTU()))
	}
	if err != nil {
		return nil, "", err
	}
	if err := waitInterfaceUp(dev, 90*time.Second, logf); err != nil {
		dev.Close()
		return nil, "", err
	}
	if err := setLinkAttrs(dev); err != nil {
		logf("setting link attributes: %v", err)
	}
	name, err := interfaceName(dev)
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	return dev, name, nil
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
