// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"sync"
	"tailscale.com/types/logger"
	"time"
)

type ifaceWatcher struct {
	lck  sync.Mutex
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
	iw.lck.Lock()
	defer iw.lck.Unlock()

	if iw.done {
		// We already know that it's up
		return true
	}

	s, err := iw.getOperStatus()
	if err != nil || s != winipcfg.IfOperStatusUp {
		return false
	}

	iw.done = true
	iw.sig <- true
	return true
}

func (iw *ifaceWatcher) getOperStatus() (winipcfg.IfOperStatus, error) {
	ifc, err := iw.luid.Interface()
	if err != nil {
		return 0, err
	}
	return ifc.OperStatus, nil
}

func waitIfaceUp(iface interface{}, timeout time.Duration, logf logger.Logf) error {
	iw := ifaceWatcher{
		luid: winipcfg.LUID(iface.(*tun.NativeTun).LUID()),
	}

	// Just in case check the status first
	s, err := iw.getOperStatus()
	if err != nil {
		logf("waitIfaceUp: iw.getOperStatus error: %v", err)
	} else if s == winipcfg.IfOperStatusUp {
		logf("waitIfaceUp: No need for callback - interface is already up.")
		return nil
	}

	iw.sig = make(chan bool, 1)
	cb, err := winipcfg.RegisterInterfaceChangeCallback(iw.callback)
	if err != nil {
		logf("waitIfaceUp: winipcfg.RegisterInterfaceChangeCallback error: %v", err)
		return err
	}
	defer cb.Unregister()

	// Check if the interface went up meanwhile.
	if iw.isUp() {
		logf("waitIfaceUp: Interface is already up.")
		return nil
	}

	logf("waitIfaceUp: Wait for interface up.")

	select {
	case <-iw.sig:
		logf("waitIfaceUp: Interface is up.")
		return nil
	case <-time.After(timeout):
		logf("waitIfaceUp: Timeout expired.")
		// Last chance - check one more time
		if iw.isUp() {
			// May happen only if NotifyIpInterfaceChange doesn't work (unlikely)
			// or if the interface went up in the same moment the timeout has expired (also unlikely)
			logf("waitIfaceUp: Interface is up after timeout expired.")
			return nil
		}
		return fmt.Errorf("timeout expired")
	}
}
