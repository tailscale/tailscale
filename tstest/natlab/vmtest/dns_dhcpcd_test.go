// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// The snippet dhcpcd's resolv.conf hook registers for the vnet NIC's DHCP
// lease: "<interface>.<protocol>".
const dhcpcdSnippet = vmtest.VnetNICName + ".dhcp"

// newDhcpcdEnv brings up a single Ubuntu node whose vnet NIC is configured
// by dhcpcd, with openresolv installed so dhcpcd's hook registers
// dhcpcdSnippet.
func newDhcpcdEnv(t *testing.T) (*vmtest.Env, *vmtest.Node) {
	t.Helper()
	env := vmtest.New(t, orControlDNS)
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.WithDNSMode(vmtest.DNSOpenresolv),
		vmtest.WithDHCPClient(vmtest.DHCPClientDhcpcd),
	)
	env.Start()

	env.AssertDNSBackend(node, "openresolv")
	assertDhcpcdLease(t, env, node, vnet.FakeDNSIPv4().String())
	return env, node
}

// assertDhcpcdLease waits for dhcpcd, not networkd, to hold the vnet NIC's
// lease, with its hook having registered dhcpcdSnippet naming the given
// nameserver. The hook runs after dhcpcd has bound the address, so this
// may briefly lag a `dhcpcd -w` that has already returned.
func assertDhcpcdLease(t *testing.T, env *vmtest.Env, n *vmtest.Node, nameserver string) {
	t.Helper()
	const cmd = "networkctl status " + vmtest.VnetNICName + " | grep -m1 State:; resolvconf -i; resolvconf -l " + dhcpcdSnippet
	var last string
	if err := tstest.WaitFor(15*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		last = out
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, "unmanaged") {
			return fmt.Errorf("networkd still manages %s", vmtest.VnetNICName)
		}
		if !slices.Contains(strings.Fields(out), dhcpcdSnippet) {
			return fmt.Errorf("resolvconf has no %s snippet", dhcpcdSnippet)
		}
		if !strings.Contains(out, "nameserver "+nameserver) {
			return fmt.Errorf("%s snippet does not name %s", dhcpcdSnippet, nameserver)
		}
		return nil
	}); err != nil {
		t.Fatalf("DHCP lease check failed: %v\nOutput:\n%s", err, last)
	}
}

// TestDhcpcdOpenresolvDNS checks the dhcpcd provisioning itself: dhcpcd holds
// the lease, its hook registered the lease's nameserver with openresolv, and
// tailscaled forwards public names there.
func TestDhcpcdOpenresolvDNS(t *testing.T) {
	env, node := newDhcpcdEnv(t)
	assertOpenresolvResolvConf(t, env, node,
		[]string{orSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()},
	)
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)
}
