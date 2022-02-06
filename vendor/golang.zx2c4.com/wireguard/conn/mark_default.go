//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

func (bind *StdNetBind) SetMark(mark uint32) error {
	return nil
}
