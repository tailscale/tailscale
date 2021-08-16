// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tun creates a tuntap device, working around OS-specific
// quirks if necessary.
package tstun

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/types/logger"
)

// tunMTU is the MTU we set on tailscale's TUN interface. wireguard-go
// defaults to 1420 bytes, which only works if the "outer" MTU is 1500
// bytes. This breaks on DSL connections (typically 1492 MTU) and on
// GCE (1460 MTU?!).
//
// 1280 is the smallest MTU allowed for IPv6, which is a sensible
// "probably works everywhere" setting until we develop proper PMTU
// discovery.
var tunMTU = 1280

func init() {
	if mtu, _ := strconv.Atoi(os.Getenv("TS_DEBUG_MTU")); mtu != 0 {
		tunMTU = mtu
	}
}

// createTAP is non-nil on Linux.
var createTAP func(tapName, bridgeName string) (tun.Device, error)

// New returns a tun.Device for the requested device name, along with
// the OS-dependent name that was allocated to the device.
func New(logf logger.Logf, tunName string) (tun.Device, string, error) {
	var dev tun.Device
	var err error
	if strings.HasPrefix(tunName, "tap:") {
		if runtime.GOOS != "linux" {
			return nil, "", errors.New("tap only works on Linux")
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
		dev, err = createTAP(tapName, bridgeName)
	} else {
		dev, err = tun.CreateTUN(tunName, tunMTU)
	}
	if err != nil {
		return nil, "", err
	}
	if err := waitInterfaceUp(dev, 90*time.Second, logf); err != nil {
		dev.Close()
		return nil, "", err
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
var tunDiagnoseFailure func(tunName string, logf logger.Logf)

// Diagnose tries to explain a tuntap device creation failure.
// It pokes around the system and logs some diagnostic info that might
// help debug why tun creation failed. Because device creation has
// already failed and the program's about to end, log a lot.
func Diagnose(logf logger.Logf, tunName string) {
	if tunDiagnoseFailure != nil {
		tunDiagnoseFailure(tunName, logf)
	} else {
		logf("no TUN failure diagnostics for OS %q", runtime.GOOS)
	}
}
