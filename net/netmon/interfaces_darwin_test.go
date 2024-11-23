// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"io"
	"net/netip"
	"os/exec"
	"testing"

	"go4.org/mem"
	"tailscale.com/util/lineiter"
	"tailscale.com/version"
)

func TestLikelyHomeRouterIPSyscallExec(t *testing.T) {
	syscallIP, _, syscallOK := likelyHomeRouterIPBSDFetchRIB()
	netstatIP, netstatIf, netstatOK := likelyHomeRouterIPDarwinExec()

	if syscallOK != netstatOK || syscallIP != netstatIP {
		t.Errorf("syscall() = %v, %v, netstat = %v, %v",
			syscallIP, syscallOK,
			netstatIP, netstatOK,
		)
	}

	if !syscallOK {
		return
	}

	def, err := defaultRoute()
	if err != nil {
		t.Errorf("defaultRoute() error: %v", err)
	}

	if def.InterfaceName != netstatIf {
		t.Errorf("syscall default route interface %s differs from netstat %s", def.InterfaceName, netstatIf)
	}
}

/*
Parse out 10.0.0.1 and en0 from:

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
func likelyHomeRouterIPDarwinExec() (ret netip.Addr, netif string, ok bool) {
	if version.IsMobile() {
		// Don't try to do subprocesses on iOS. Ends up with log spam like:
		// kernel: "Sandbox: IPNExtension(86580) deny(1) process-fork"
		// This is why we have likelyHomeRouterIPDarwinSyscall.
		return ret, "", false
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
	defer io.Copy(io.Discard, stdout) // clear the pipe to prevent hangs

	var f []mem.RO
	for lr := range lineiter.Reader(stdout) {
		lineb, err := lr.Value()
		if err != nil {
			break
		}
		line := mem.B(lineb)
		if !mem.Contains(line, mem.S("default")) {
			continue
		}
		f = mem.AppendFields(f[:0], line)
		if len(f) < 4 || !f[0].EqualString("default") {
			continue
		}
		ipm, flagsm, netifm := f[1], f[2], f[3]
		if !mem.Contains(flagsm, mem.S("G")) {
			continue
		}
		if mem.Contains(flagsm, mem.S("I")) {
			continue
		}
		ip, err := netip.ParseAddr(string(mem.Append(nil, ipm)))
		if err == nil && ip.IsPrivate() {
			ret = ip
			netif = netifm.StringCopy()
			// We've found what we're looking for.
			break
		}
	}
	return ret, netif, ret.IsValid()
}

func TestFetchRoutingTable(t *testing.T) {
	// Issue 1345: this used to be flaky on darwin.
	for range 20 {
		_, err := fetchRoutingTable()
		if err != nil {
			t.Fatal(err)
		}
	}
}
