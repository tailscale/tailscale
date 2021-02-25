// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/types/logger"
)

type ifaceWatcher struct {
	logf logger.Logf
	luid winipcfg.LUID

	mu   sync.Mutex
	done bool
	sig  chan bool
}

// callback is the callback we register with Windows to call when IP interface changes.
func (iw *ifaceWatcher) callback(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
	// Probably should check only when MibParameterNotification, but just in case included MibAddInstance also.
	if notificationType == winipcfg.MibParameterNotification || notificationType == winipcfg.MibAddInstance {
		// Out of paranoia, start a goroutine to finish our work, to return to Windows out of this callback.
		go iw.isUp()
	}
}

func (iw *ifaceWatcher) isUp() bool {
	iw.mu.Lock()
	defer iw.mu.Unlock()

	if iw.done {
		// We already know that it's up
		return true
	}

	if iw.getOperStatus() != winipcfg.IfOperStatusUp {
		return false
	}

	iw.done = true
	iw.sig <- true
	return true
}

func (iw *ifaceWatcher) getOperStatus() winipcfg.IfOperStatus {
	ifc, err := iw.luid.Interface()
	if err != nil {
		iw.logf("iw.luid.Interface error: %v", err)
		return 0
	}
	return ifc.OperStatus
}

func waitInterfaceUp(iface tun.Device, timeout time.Duration, logf logger.Logf) error {
	iw := &ifaceWatcher{
		luid: winipcfg.LUID(iface.(*tun.NativeTun).LUID()),
		logf: logger.WithPrefix(logf, "waitIfaceUp: "),
	}

	// Just in case check the status first
	if iw.getOperStatus() == winipcfg.IfOperStatusUp {
		iw.logf("interface already up; no need to wait")
		return nil
	}

	iw.sig = make(chan bool, 1)
	cb, err := winipcfg.RegisterInterfaceChangeCallback(iw.callback)
	if err != nil {
		iw.logf("winipcfg.RegisterInterfaceChangeCallback error: %v", err)
		return err
	}
	defer cb.Unregister()

	// Check if the interface went up meanwhile.
	if iw.isUp() {
		iw.logf("interface is already up")
		return nil
	}

	expires := time.Now().UTC().Add(timeout)
	tmr := time.NewTicker(10 * time.Second)
	defer tmr.Stop()

	for {
		iw.logf("waiting for interface to come up...")

		select {
		case <-iw.sig:
			iw.logf("interface is up")
			return nil
		case <-tmr.C:
			break;
		}

		if iw.isUp() {
			// Very unlikely to happen - either NotifyIpInterfaceChange doesn't work
			// or it came up in the same moment as tick. Indicate this in the log message.
			iw.logf("[tick] interface is up")
			return nil
		}

		if expires.Before(time.Now().UTC()) {
			iw.logf("timeout expired")
			return fmt.Errorf("timeout expired")
		}
	}
}
