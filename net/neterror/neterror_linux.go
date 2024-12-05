// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	shouldDisableUDPGSO = func(err error) bool {
		var serr *os.SyscallError
		if errors.As(err, &serr) {
			// EIO is returned by udp_send_skb() if the device driver does not
			// have tx checksumming enabled, which is a hard requirement of
			// UDP_SEGMENT. See:
			// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
			// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
			return serr.Err == unix.EIO
		}
		return false
	}
}
