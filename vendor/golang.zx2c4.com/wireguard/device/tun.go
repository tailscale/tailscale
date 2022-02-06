/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	device.log.Verbosef("Routine: event worker - started")

	for event := range device.tun.device.Events() {
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			if err != nil {
				device.log.Errorf("Failed to load updated MTU of device: %v", err)
				continue
			}
			if mtu < 0 {
				device.log.Errorf("MTU not updated to negative value: %v", mtu)
				continue
			}
			var tooLarge string
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %v)", MaxContentSize)
				mtu = MaxContentSize
			}
			old := atomic.SwapInt32(&device.tun.mtu, int32(mtu))
			if int(old) != mtu {
				device.log.Verbosef("MTU updated: %v%s", mtu, tooLarge)
			}
		}

		if event&tun.EventUp != 0 {
			device.log.Verbosef("Interface up requested")
			device.Up()
		}

		if event&tun.EventDown != 0 {
			device.log.Verbosef("Interface down requested")
			device.Down()
		}
	}

	device.log.Verbosef("Routine: event worker - stopped")
}
