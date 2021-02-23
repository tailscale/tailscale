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
	mu   sync.Mutex
	logf logger.Logf
	luid winipcfg.LUID
	done bool
	sig  chan bool
}

func (iw *ifaceWatcher) callback(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
	// Probably should check only when MibParameterNotification, but just in case included MibAddInstance also.
	if notificationType == winipcfg.MibParameterNotification || notificationType == winipcfg.MibAddInstance {
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

func waitIfaceUp(iface tun.Device, timeout time.Duration, logf logger.Logf) error {
	iw := &ifaceWatcher{
		luid: winipcfg.LUID(iface.(*tun.NativeTun).LUID()),
		logf: logger.WithPrefix(logf, "waitIfaceUp: "),
	}

	// Just in case check the status first
	if iw.getOperStatus() == winipcfg.IfOperStatusUp {
		iw.logf("no need for callback - interface is already up")
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

	iw.logf("waiting for interface to come up...")

	tmr := time.NewTimer(timeout)

	select {
	case <-iw.sig:
		tmr.Stop()
		iw.logf("interface is up")
		return nil
	case <-tmr.C:
		iw.logf("timeout expired")
		// Last chance - check one more time
		if iw.isUp() {
			// May happen only if NotifyIpInterfaceChange doesn't work (unlikely)
			// or if the interface went up in the same moment the timeout has expired (also unlikely)
			iw.logf("interface is up after timeout expired")
			return nil
		}
		return fmt.Errorf("timeout expired")
	}
}
