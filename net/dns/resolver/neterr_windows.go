// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/windows"
)

func networkIsDown(err error) bool {
	if oe, ok := err.(*net.OpError); ok && oe.Op == "write" {
		if se, ok := oe.Err.(*os.SyscallError); ok {
			if se.Syscall == "wsasendto" && se.Err == windows.WSAENETUNREACH {
				return true
			}
		}
	}
	return false
}

func networkIsUnreachable(err error) bool {
	// TODO(bradfitz,josharian): something here? what is the
	// difference between down and unreachable? Add comments.
	return false
}

// packetWasTruncated returns true if err indicates truncation but the RecvFrom
// that generated err was otherwise successful. On Windows, Go's UDP RecvFrom
// calls WSARecvFrom which returns the WSAEMSGSIZE error code when the received
// datagram is larger than the provided buffer. When that happens, both a valid
// size and an error are returned (as per the partial fix for golang/go#14074).
// If the WSAEMSGSIZE error is returned, then we ignore the error to get
// semantics similar to the POSIX operating systems. One caveat is that it
// appears that the source address is not returned when WSAEMSGSIZE occurs, but
// we do not currently look at the source address.
func packetWasTruncated(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
