// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	shouldDisableUDPGSO = func(err error) bool {
		if serr, ok := errors.AsType[*os.SyscallError](err); ok {
			// EIO is returned by udp_send_skb() if the device driver does not
			// have tx checksumming enabled, which is a hard requirement of
			// UDP_SEGMENT. See:
			// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
			// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
			return serr.Err == unix.EIO
		}
		return false
	}

	shouldRetryWithoutUDPGSO = func(err error) bool {
		if serr, ok := errors.AsType[*os.SyscallError](err); ok {
			// EMSGSIZE is returned when the packet cannot fit the path MTU.
			// EINVAL is returned by older kernels for the same constrained-path
			// UDP GSO case. Both errors are recoverable by retrying this batch
			// without GSO; they should not disable GSO for the whole socket.
			return serr.Err == unix.EIO || serr.Err == unix.EMSGSIZE || serr.Err == unix.EINVAL
		}
		return false
	}
}
