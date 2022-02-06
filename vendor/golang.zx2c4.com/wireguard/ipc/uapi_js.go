/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 WireGuard LLC. All Rights Reserved.
 */

package ipc

// Made up sentinel error codes for the js/wasm platform.
const (
	IpcErrorIO        = 1
	IpcErrorInvalid   = 2
	IpcErrorPortInUse = 3
	IpcErrorUnknown   = 4
	IpcErrorProtocol  = 5
)
