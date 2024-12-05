// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"fmt"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/types/logger"
)

// ifaceWatcher waits for an interface to be up.
type ifaceWatcher struct {
	logf logger.Logf
	luid winipcfg.LUID

	mu   sync.Mutex // guards following
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
		logf: logger.WithPrefix(logf, "waitInterfaceUp: "),
	}

	// Just in case check the status first
	if iw.getOperStatus() == winipcfg.IfOperStatusUp {
		iw.logf("TUN interface already up; no need to wait")
		return nil
	}

	iw.sig = make(chan bool, 1)
	cb, err := winipcfg.RegisterInterfaceChangeCallback(iw.callback)
	if err != nil {
		iw.logf("RegisterInterfaceChangeCallback error: %v", err)
		return err
	}
	defer cb.Unregister()

	t0 := time.Now()
	expires := t0.Add(timeout)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		iw.logf("waiting for TUN interface to come up...")

		select {
		case <-iw.sig:
			iw.logf("TUN interface is up after %v", time.Since(t0))
			return nil
		case <-ticker.C:
		}

		if iw.isUp() {
			// Very unlikely to happen - either NotifyIpInterfaceChange doesn't work
			// or it came up in the same moment as tick. Indicate this in the log message.
			iw.logf("TUN interface is up after %v (on poll, without notification)", time.Since(t0))
			return nil
		}

		if expires.Before(time.Now()) {
			iw.logf("timeout waiting %v for TUN interface to come up", timeout)
			return fmt.Errorf("timeout waiting for TUN interface to come up")
		}
	}
}
