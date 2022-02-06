/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// InterfaceChangeCallback structure allows interface change callback handling.
type InterfaceChangeCallback struct {
	cb   func(notificationType MibNotificationType, iface *MibIPInterfaceRow)
	wait sync.WaitGroup
}

var (
	interfaceChangeAddRemoveMutex = sync.Mutex{}
	interfaceChangeMutex          = sync.Mutex{}
	interfaceChangeCallbacks      = make(map[*InterfaceChangeCallback]bool)
	interfaceChangeHandle         = windows.Handle(0)
)

// RegisterInterfaceChangeCallback registers a new InterfaceChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned InterfaceChangeCallback.Unregister method should be used
// to unregister.
func RegisterInterfaceChangeCallback(callback func(notificationType MibNotificationType, iface *MibIPInterfaceRow)) (*InterfaceChangeCallback, error) {
	s := &InterfaceChangeCallback{cb: callback}

	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	interfaceChangeMutex.Lock()
	defer interfaceChangeMutex.Unlock()

	interfaceChangeCallbacks[s] = true

	if interfaceChangeHandle == 0 {
		err := notifyIPInterfaceChange(windows.AF_UNSPEC, windows.NewCallback(interfaceChanged), 0, false, &interfaceChangeHandle)
		if err != nil {
			delete(interfaceChangeCallbacks, s)
			interfaceChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *InterfaceChangeCallback) Unregister() error {
	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	interfaceChangeMutex.Lock()
	delete(interfaceChangeCallbacks, callback)
	removeIt := len(interfaceChangeCallbacks) == 0 && interfaceChangeHandle != 0
	interfaceChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(interfaceChangeHandle)
		if err != nil {
			return err
		}
		interfaceChangeHandle = 0
	}

	return nil
}

func interfaceChanged(callerContext uintptr, row *MibIPInterfaceRow, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	interfaceChangeMutex.Lock()
	for cb := range interfaceChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *InterfaceChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	interfaceChangeMutex.Unlock()
	return 0
}
