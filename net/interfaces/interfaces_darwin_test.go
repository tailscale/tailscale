// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"errors"
	"net/netip"
	"os/exec"
	"testing"

	"go4.org/mem"
	"tailscale.com/net/netaddr"
	"tailscale.com/util/lineread"
	"tailscale.com/version"
)

func TestLikelyHomeRouterIPSyscallExec(t *testing.T) {
	syscallIP, syscallOK := likelyHomeRouterIPDarwinFetchRIB()
	netstatIP, netstatOK := likelyHomeRouterIPDarwinExec()
	if syscallOK != netstatOK || syscallIP != netstatIP {
		t.Errorf("syscall() = %v, %v, netstat = %v, %v",
			syscallIP, syscallOK,
			netstatIP, netstatOK,
		)
	}
}

/*
Parse out 10.0.0.1 from:

$ netstat -r -n -f inet
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGSc           en0
default            link#14            UCSI         utun2
10/16              link#4             UCS            en0      !
10.0.0.1/32        link#4             UCS            en0      !
...

*/
func likelyHomeRouterIPDarwinExec() (ret netaddr.IP, ok bool) {
	if version.IsMobile() {
		// Don't try to do subprocesses on iOS. Ends up with log spam like:
		// kernel: "Sandbox: IPNExtension(86580) deny(1) process-fork"
		// This is why we have likelyHomeRouterIPDarwinSyscall.
		return ret, false
	}
	cmd := exec.Command("/usr/sbin/netstat", "-r", "-n", "-f", "inet")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer cmd.Wait()

	var f []mem.RO
	lineread.Reader(stdout, func(lineb []byte) error {
		line := mem.B(lineb)
		if !mem.Contains(line, mem.S("default")) {
			return nil
		}
		f = mem.AppendFields(f[:0], line)
		if len(f) < 3 || !f[0].EqualString("default") {
			return nil
		}
		ipm, flagsm := f[1], f[2]
		if !mem.Contains(flagsm, mem.S("G")) {
			return nil
		}
		ip, err := netip.ParseAddr(string(mem.Append(nil, ipm)))
		if err == nil && ip.IsPrivate() {
			ret = ip
			// We've found what we're looking for.
			return errStopReadingNetstatTable
		}
		return nil
	})
	return ret, ret.IsValid()
}

func TestFetchRoutingTable(t *testing.T) {
	// Issue 1345: this used to be flaky on darwin.
	for i := 0; i < 20; i++ {
		_, err := fetchRoutingTable()
		if err != nil {
			t.Fatal(err)
		}
	}
}

var errStopReadingNetstatTable = errors.New("found private gateway")
