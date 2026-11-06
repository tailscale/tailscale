// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/cmd/tailscale/tsdnsjsonv0"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
)

// The openresolv tests use a routed domain that is answered locally from an
// extra record. That is the cheapest DNS config that still reaches
// GetBaseConfig. It has no default resolvers, which would short-circuit
// compileConfig. It also takes no split-DNS shortcut, because openresolv
// reports SupportsSplitDNS() == false.
const (
	orMagicDNSDomain = "tailnet.test"
	orLocalDomain    = "local.example"
	orLocalName      = "host." + orLocalDomain

	// This address is outside the 100.64.x.y block testcontrol assigns to
	// nodes, so an answer can only have come from the extra record.
	orLocalIP = "100.99.99.99"

	// A name that no route covers and that only vnet's default DNS server
	// answers. Resolving it proves the query reached the base config's
	// nameservers instead of being answered by quad-100.
	orUpstreamOnlyName = "dualstack-web.example.com"
	orUpstreamOnlyIP   = "5.0.0.100"

	// Tailscale's own resolver. tailscaled points resolv.conf at it once it has
	// configured DNS.
	orQuad100 = "100.100.100.100"
)

// orControlDNS is the control DNS config the openresolv tests share.
var orControlDNS = vmtest.ControlDNS(orMagicDNSDomain, &tailcfg.DNSConfig{
	Proxied: true, // MagicDNS, so there's a route and quad-100 is in play
	Domains: []string{orLocalDomain},
	Routes: map[string][]*dnstype.Resolver{
		orLocalDomain: nil, // answer locally, from ExtraRecords
	},
	ExtraRecords: []tailcfg.DNSRecord{
		{Name: orLocalName, Type: "A", Value: orLocalIP},
	},
})

// newOpenresolvEnv brings up a single node of the given image running
// openresolv with an existing but empty snippet directory, so openresolv has
// no snippets registered until something adds one. On Linux that is the
// vendored upstream openresolv; on FreeBSD it is the one in the base system.
func newOpenresolvEnv(t *testing.T, img vmtest.OSImage) (*vmtest.Env, *vmtest.Node) {
	t.Helper()
	env := vmtest.New(t, orControlDNS)
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(img),
		vmtest.WithDNSMode(vmtest.DNSOpenresolv))
	env.Start()

	// Otherwise a pass could come from a different DNS manager.
	env.AssertDNSBackend(node, "openresolv")
	return env, node
}

// TestOpenresolvDNS checks what tailscaled does on a host where openresolv has
// no snippets registered, so Tailscale's would be the only one. Before the fix
// for tailscale/tailscale#20825, resolvconf's exit status 2 aborted DNS
// configuration with a health error. Now openresolv reports an empty base
// config, so tailscaled has no upstream to forward public names to. It leaves
// resolv.conf alone and reports that it is waiting for system DNS servers
// (tailscale/tailscale#20341).
func TestOpenresolvDNS(t *testing.T) {
	testOpenresolvDNS(t, vmtest.Ubuntu2404, 2)
}

// TestOpenresolvDNSFreeBSD is TestOpenresolvDNS on the openresolv in
// FreeBSD's base system. That version reports an empty snippet directory
// with exit status 1 rather than 2. See tailscale/tailscale#11907.
func TestOpenresolvDNSFreeBSD(t *testing.T) {
	testOpenresolvDNS(t, vmtest.FreeBSD150, 1)
}

// testOpenresolvDNS is the body of TestOpenresolvDNS. wantListExit is the exit
// status the image's openresolv uses for "resolvconf -i" with no snippets.
func testOpenresolvDNS(t *testing.T, img vmtest.OSImage, wantListExit int) {
	env, node := newOpenresolvEnv(t, img)

	// Wait for tailscaled to report that it is holding off. Checking
	// resolv.conf alone proves nothing, since the file also looks untouched
	// before tailscaled has tried.
	assertEmptyBaseConfigWarning(t, env, node)

	// resolv.conf keeps the nameserver natlab provisioned, and quad-100 is not
	// installed, since it would have nothing to forward public names to.
	assertOpenresolvResolvConf(t, env, node,
		[]string{vmtest.OpenresolvSignature, vnet.FakeDNSIPv4().String()},
		[]string{orQuad100})

	// An empty base config is not a read failure.
	assertNoDNSReadWarning(t, env, node)

	// Tailscale did not register its snippet, so openresolv still has none.
	// The exit status says which openresolv behavior the image exercises.
	const cmd = "resolvconf -i; echo rc=$?"
	want := []string{fmt.Sprintf("rc=%d", wantListExit)}
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	} else if got := strings.Fields(out); !slices.Equal(got, want) {
		t.Errorf("%s = %q, want no snippets and exit status %d", cmd, strings.TrimSpace(out), wantListExit)
	}

	// The provisioned resolv.conf still works for public names.
	assertResolves(t, env, node, img, orUpstreamOnlyName, orUpstreamOnlyIP)

	// openresolv has no snippets, so it has no OS config to report: both the
	// nameservers and the search domains must come back empty, with no error.
	base := openresolvBaseConfig(t, env, node)
	if base == nil {
		return // openresolvBaseConfig already reported it
	}
	if len(base.Nameservers) != 0 || len(base.SearchDomains) != 0 {
		t.Errorf("OS base config = %+v, want it empty: openresolv has no "+
			"snippets, so it has no OS config to report "+
			"(tailscale/tailscale#20825)", *base)
	}
}

// TestOpenresolvDNSOtherSnippet is the counterweight to TestOpenresolvDNS.
// When another snippet is present, its nameservers must still become quad-100's
// default upstream. Without this test, the fix for #20825 could return early on
// every host and still look correct.
func TestOpenresolvDNSOtherSnippet(t *testing.T) {
	testOpenresolvDNSOtherSnippet(t, vmtest.Ubuntu2404)
}

// TestOpenresolvDNSOtherSnippetFreeBSD is TestOpenresolvDNSOtherSnippet on
// the openresolv in FreeBSD's base system. It is also the normal state of a
// FreeBSD host with DHCP, where dhclient registers a snippet for each NIC.
func TestOpenresolvDNSOtherSnippetFreeBSD(t *testing.T) {
	testOpenresolvDNSOtherSnippet(t, vmtest.FreeBSD150)
}

// testOpenresolvDNSOtherSnippet is the body of TestOpenresolvDNSOtherSnippet.
func testOpenresolvDNSOtherSnippet(t *testing.T, img vmtest.OSImage) {
	env, node := newOpenresolvEnv(t, img)

	// Register a second snippet, the way a DHCP client would. It points at
	// vnet's default DNS server, the only thing that answers
	// orUpstreamOnlyName.
	cmd := fmt.Sprintf("printf 'nameserver %s\\n' | resolvconf -a eth0.inet", vnet.FakeDNSIPv4())
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}

	// tailscaled has no reason to re-read the OS config on its own, so force a
	// full reapply. This is also how the reporter of #20825 reproduced the bug.
	env.SetAcceptDNS(node, false)
	env.SetAcceptDNS(node, true)

	// Both snippets are registered.
	if out, err := env.SSHExec(node, "resolvconf -i"); err != nil {
		t.Errorf("resolvconf -i: %v (%s)", err, strings.TrimSpace(out))
	} else {
		// Match whole fields, so "tailscale" does not match a longer snippet
		// name.
		got := strings.Fields(out)
		for _, want := range []string{"eth0.inet", "tailscale"} {
			if !slices.Contains(got, want) {
				t.Errorf("resolvconf -i = %q, want it to list %q", strings.TrimSpace(out), want)
			}
		}
	}

	// Tailscale still owns resolv.conf, so the OS asks quad-100 rather than the
	// other snippet directly. Check that before the lookup at the end of the
	// test. Otherwise a successful lookup might only mean libc went straight to
	// the other snippet's nameserver during the toggle above.
	assertOpenresolvResolvConf(t, env, node,
		[]string{vmtest.OpenresolvSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()})

	assertNoDNSReadWarning(t, env, node)

	// tailscaled must read back the other snippet's nameserver and nothing else.
	// An empty config would mean the #20825 early return fired when it should
	// not have, and our own snippet would mean the quad-100 filter did not
	// (tailscale/tailscale#7816).
	if base := openresolvBaseConfig(t, env, node); base != nil {
		if want := vnet.FakeDNSIPv4().String(); !slices.Equal(base.Nameservers, []string{want}) {
			t.Errorf("OS base config nameservers = %q, want just %s", base.Nameservers, want)
		}
	}

	// An answer here can only come from quad-100 forwarding to that base config,
	// since nothing else on the guest answers this name.
	assertResolves(t, env, node, img, orUpstreamOnlyName, orUpstreamOnlyIP)
}

// assertOpenresolvResolvConf waits for the guest's /etc/resolv.conf to contain
// every string in want and none in notWant.
func assertOpenresolvResolvConf(t *testing.T, env *vmtest.Env, n *vmtest.Node, want, notWant []string) {
	t.Helper()
	const cmd = "cat /etc/resolv.conf"
	var last string
	if err := tstest.WaitFor(60*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		last = out
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				return fmt.Errorf("resolv.conf is missing %q", w)
			}
		}
		for _, w := range notWant {
			if strings.Contains(out, w) {
				return fmt.Errorf("resolv.conf unexpectedly has %q", w)
			}
		}
		return nil
	}); err != nil {
		// The health lines are the fastest way to tell "DNS was never applied"
		// from "DNS was applied but looks wrong".
		t.Fatalf("%v\nwant all of %q and none of %q in resolv.conf:\n%s\nhealth: %q",
			err, want, notWant, last, env.Status(n).Health)
	}
}

// openresolvBaseConfig returns what tailscaled reads back as the node's own OS
// DNS configuration. On failure it calls t.Errorf and returns nil.
//
// "tailscale dns status" fetches it over the local API, which calls straight
// through to openresolvManager.GetBaseConfig, so this is the live result of
// running resolvconf in the guest, not something inferred from its consequences.
func openresolvBaseConfig(t *testing.T, env *vmtest.Env, n *vmtest.Node) *tsdnsjsonv0.SystemConfig {
	t.Helper()
	const cmd = "tailscale dns status --json"
	out, err := env.SSHExec(n, cmd)
	if err != nil {
		t.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		return nil
	}
	var st tsdnsjsonv0.StatusResponse
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Errorf("parsing %s output: %v\n%s", cmd, err, out)
		return nil
	}
	if st.SystemDNSError != "" {
		t.Errorf("tailscaled could not read the OS DNS config: %q", st.SystemDNSError)
		return nil
	}
	if st.SystemDNS == nil {
		t.Errorf("%s reported no OS DNS config:\n%s", cmd, out)
		return nil
	}
	return st.SystemDNS
}

// assertEmptyBaseConfigWarning waits until the node's health list includes the
// warning that the OS has no DNS servers for Tailscale to forward to.
func assertEmptyBaseConfigWarning(t *testing.T, env *vmtest.Env, n *vmtest.Node) {
	t.Helper()
	// Taking the text from the Warnable rather than copying its wording keeps
	// this check from silently going stale if the wording changes.
	want := dns.EmptyBaseConfigWarnable.Text(nil)
	var last []string
	if err := tstest.WaitFor(60*time.Second, func() error {
		last = env.Status(n).Health
		if slices.Contains(last, want) {
			return nil
		}
		return fmt.Errorf("health does not include %q", want)
	}); err != nil {
		t.Fatalf("%v\nhealth: %q", err, last)
	}
}

// assertNoDNSReadWarning fails if the node is reporting that it could not read
// the OS DNS configuration.
func assertNoDNSReadWarning(t *testing.T, env *vmtest.Env, n *vmtest.Node) {
	t.Helper()
	// The warning ends with the error text, so match on what comes before it.
	// Taking that from the Warnable rather than copying its wording matters
	// here: this check asserts an absence, so a copy that stopped matching
	// would leave the check passing while testing nothing.
	want := dns.OSConfigurationReadWarnable.Text(health.Args{health.ArgError: ""})
	for _, h := range env.Status(n).Health {
		if strings.HasPrefix(h, want) {
			t.Errorf("node is unhealthy: %q", h)
		}
	}
}

// resolveIPv4Cmd returns the guest command that resolves name to IPv4
// addresses through the guest's resolv.conf. Asking for IPv4 only means a
// name with both an A and a AAAA record cannot come back as the wrong address
// family.
//
// On Linux the lookup goes through libc. FreeBSD's getent has no ahostsv4
// database and its hosts database prefers AAAA, so there the lookup uses
// host(1), which reads resolv.conf like libc does.
func resolveIPv4Cmd(img vmtest.OSImage, name string) string {
	if img.GOOS() == "freebsd" {
		return "host -t A " + name
	}
	return "getent ahostsv4 " + name
}

// assertResolves waits for name to resolve to want on the node.
func assertResolves(t *testing.T, env *vmtest.Env, n *vmtest.Node, img vmtest.OSImage, name, want string) {
	t.Helper()
	cmd := resolveIPv4Cmd(img, name)
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("%s = %q, want it to contain %s", cmd, strings.TrimSpace(out), want)
		}
		return nil
	}); err != nil {
		out, _ := env.SSHExec(n, "cat /etc/resolv.conf; resolvconf -i")
		t.Errorf("%v\nresolver state:\n%s", err, out)
	}
}
