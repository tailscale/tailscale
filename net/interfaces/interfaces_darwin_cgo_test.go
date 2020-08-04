// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo,darwin

package interfaces

import "testing"

func TestLikelyHomeRouterIPSyscallExec(t *testing.T) {
	syscallIP, syscallOK := likelyHomeRouterIPDarwinSyscall()
	netstatIP, netstatOK := likelyHomeRouterIPDarwinExec()
	if syscallOK != netstatOK || syscallIP != netstatIP {
		t.Errorf("syscall() = %v, %v, netstat = %v, %v",
			syscallIP, syscallOK,
			netstatIP, netstatOK,
		)
	}
}
