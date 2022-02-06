/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"os"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

type Device interface {
	File() *os.File                 // returns the file descriptor of the device
	Read([]byte, int) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte, int) (int, error) // writes a packet to the device (without any additional headers)
	Flush() error                   // flush all previous writes to the device
	MTU() (int, error)              // returns the MTU of the device
	Name() (string, error)          // fetches and returns the current name
	Events() chan Event             // returns a constant channel of events related to the device
	Close() error                   // stops the device and closes the event channel
}
