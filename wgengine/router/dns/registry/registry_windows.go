// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// The code in this file is originally written for https://git.zx2c4.com/wireguard-go/ by:
// Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
// Copying license: https://git.zx2c4.com/wireguard-go/tree/COPYING

// TODO(peske): Check the file header ^^^ to ensure appropriate copyright info.
package registry

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// REG_NOTIFY_CHANGE_NAME notifies the caller if a subkey is added or deleted.
	REG_NOTIFY_CHANGE_NAME uint32 = 0x00000001
)

//sys	regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error) = advapi32.RegNotifyChangeKeyValue

func OpenKeyWait(k registry.Key, path string, access uint32, timeout time.Duration) (registry.Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	deadline := time.Now().Add(timeout)
	pathSpl := strings.Split(path, "\\")
	for i := 0; ; i++ {
		keyName := pathSpl[i]
		isLast := i+1 == len(pathSpl)

		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return 0, fmt.Errorf("Error creating event: %v", err)
		}
		defer windows.CloseHandle(event)

		var key registry.Key
		for {
			err = regNotifyChangeKeyValue(windows.Handle(k), false, REG_NOTIFY_CHANGE_NAME, windows.Handle(event), true)
			if err != nil {
				return 0, fmt.Errorf("Setting up change notification on registry key failed: %v", err)
			}

			var accessFlags uint32
			if isLast {
				accessFlags = access
			} else {
				accessFlags = registry.NOTIFY
			}
			key, err = registry.OpenKey(k, keyName, accessFlags)
			if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
				timeout := time.Until(deadline) / time.Millisecond
				if timeout < 0 {
					timeout = 0
				}
				s, err := windows.WaitForSingleObject(event, uint32(timeout))
				if err != nil {
					return 0, fmt.Errorf("Unable to wait on registry key: %v", err)
				}
				if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
					return 0, errors.New("Timeout waiting for registry key")
				}
			} else if err != nil {
				return 0, fmt.Errorf("Error opening registry key %v: %v", path, err)
			} else {
				if isLast {
					return key, nil
				}
				defer key.Close()
				break
			}
		}

		k = key
	}
}
