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
func newDhcpcdEnv(t *testing.T) (*vmtest.Env, *vmtest.Node, *vnet.Network) {
	t.Helper()
	env := vmtest.New(t, orControlDNS)
	nw := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	node := env.AddNode("node", nw,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.WithDNSMode(vmtest.DNSOpenresolv),
		vmtest.WithDHCPClient(vmtest.DHCPClientDhcpcd),
	)
	env.Start()

	env.AssertDNSBackend(node, "openresolv")
	assertDhcpcdLease(t, env, node, vnet.FakeDNSIPv4().String())
	return env, node, nw
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
	env, node, _ := newDhcpcdEnv(t)
	assertOpenresolvResolvConf(t, env, node,
		[]string{orSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()},
	)
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)
}

// TestDhcpcdLeaseRebind checks that tailscaled picks up the DNS servers a
// DHCP lease carries when dhcpcd releases the lease and binds a new one.
// dhcpcd configures the address first and runs its resolv.conf hook
// afterwards; here the hook is slowed by a few seconds so that order is
// certain. See tailscale/tailscale#21607.
func TestDhcpcdLeaseRebind(t *testing.T) {
	t.Skip("tailscaled re-sets DNS before dhcpcd's resolvconf hook runs and does not re-read it afterwards; see https://github.com/tailscale/tailscale/issues/21607")
	env, node, _ := newDhcpcdEnv(t)

	// A router-advertised nameserver that nothing answers. vnet sends no
	// router advertisements, so the snippet dhcpcd would register for one is
	// added by hand. It outlives the DHCP lease.
	addOpenresolvSnippet(t, env, node, vmtest.VnetNICName+".ra", orDeadNameserver)
	env.SetAcceptDNS(node, false)
	env.SetAcceptDNS(node, true)
	assertOpenresolvResolvConf(t, env, node,
		[]string{orSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()})
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)

	// Slow every hook run, then release the lease and bind a new one. The
	// release removes the address, and its hook removes dhcpcdSnippet. The
	// bind adds the address back, and its hook adds dhcpcdSnippet back once
	// the delay has passed. The network monitor can report an address add
	// twice, about a second apart, so the delay is longer than that.
	cmd := fmt.Sprintf("printf 'sleep 3\\n' > %s && dhcpcd -k %[2]s && dhcpcd -w %[2]s",
		vmtest.DhcpcdEnterHook, vmtest.VnetNICName)
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}
	assertDhcpcdLease(t, env, node, vnet.FakeDNSIPv4().String())

	// Public names must still resolve.
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)
}

// TestDhcpcdRenewalChangesDNS checks that tailscaled picks up new DNS servers
// delivered by a lease renewal. The renewal keeps the address, so there is no
// netlink event; dhcpcd's hook re-registers dhcpcdSnippet with the new
// servers. See tailscale/tailscale#21607.
func TestDhcpcdRenewalChangesDNS(t *testing.T) {
	t.Skip("tailscaled does not notice new DNS servers from a lease renewal; see https://github.com/tailscale/tailscale/issues/21607")
	env, node, nw := newDhcpcdEnv(t)
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)

	// The DHCP server switches to a nameserver that answers only
	// vnet.SplitDNSName, and the client renews.
	nw.SetDHCPDNS(vnet.FakeSplitDNSIPv4())
	cmd := "dhcpcd -n " + vmtest.VnetNICName
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(node, "resolvconf -l "+dhcpcdSnippet)
		if err != nil {
			return err
		}
		if !strings.Contains(out, vnet.FakeSplitDNSIPv4().String()) {
			return fmt.Errorf("%s still reads:\n%s", dhcpcdSnippet, out)
		}
		return nil
	}); err != nil {
		t.Fatalf("renewal did not deliver the new nameserver: %v", err)
	}

	// tailscaled can read the new nameserver back.
	if base := openresolvBaseConfig(t, env, node); base != nil {
		if want := vnet.FakeSplitDNSIPv4().String(); !slices.Equal(base.Nameservers, []string{want}) {
			t.Fatalf("OS base config nameservers after renewal = %q, want just %s", base.Nameservers, want)
		}
	}

	// A name only the new nameserver answers must resolve through quad-100.
	assertResolves(t, env, node, vnet.SplitDNSName, vnet.SplitDNSAddr)
}
