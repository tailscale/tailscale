/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// UnicastAddressChangeCallback structure allows unicast address change callback handling.
type UnicastAddressChangeCallback struct {
	cb   func(notificationType MibNotificationType, unicastAddress *MibUnicastIPAddressRow)
	wait sync.WaitGroup
}

var (
	unicastAddressChangeAddRemoveMutex = sync.Mutex{}
	unicastAddressChangeMutex          = sync.Mutex{}
	unicastAddressChangeCallbacks      = make(map[*UnicastAddressChangeCallback]bool)
	unicastAddressChangeHandle         = windows.Handle(0)
)

// RegisterUnicastAddressChangeCallback registers a new UnicastAddressChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned UnicastAddressChangeCallback.Unregister method should be used
// to unregister.
func RegisterUnicastAddressChangeCallback(callback func(notificationType MibNotificationType, unicastAddress *MibUnicastIPAddressRow)) (*UnicastAddressChangeCallback, error) {
	s := &UnicastAddressChangeCallback{cb: callback}

	unicastAddressChangeAddRemoveMutex.Lock()
	defer unicastAddressChangeAddRemoveMutex.Unlock()

	unicastAddressChangeMutex.Lock()
	defer unicastAddressChangeMutex.Unlock()

	unicastAddressChangeCallbacks[s] = true

	if unicastAddressChangeHandle == 0 {
		err := notifyUnicastIPAddressChange(windows.AF_UNSPEC, windows.NewCallback(unicastAddressChanged), 0, false, &unicastAddressChangeHandle)
		if err != nil {
			delete(unicastAddressChangeCallbacks, s)
			unicastAddressChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *UnicastAddressChangeCallback) Unregister() error {
	unicastAddressChangeAddRemoveMutex.Lock()
	defer unicastAddressChangeAddRemoveMutex.Unlock()

	unicastAddressChangeMutex.Lock()
	delete(unicastAddressChangeCallbacks, callback)
	removeIt := len(unicastAddressChangeCallbacks) == 0 && unicastAddressChangeHandle != 0
	unicastAddressChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(unicastAddressChangeHandle)
		if err != nil {
			return err
		}
		unicastAddressChangeHandle = 0
	}

	return nil
}

func unicastAddressChanged(callerContext uintptr, row *MibUnicastIPAddressRow, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	unicastAddressChangeMutex.Lock()
	for cb := range unicastAddressChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *UnicastAddressChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	unicastAddressChangeMutex.Unlock()
	return 0
}
