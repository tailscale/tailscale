// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

// TestMagicDNS verifies that control-plane DNS config makes it all the
// way into an Ubuntu guest's OS resolver, and that MagicDNS answers
// track netmap changes. Booting a VM is expensive, so this one test
// covers several scenarios in sequence:
//
//   - DNSConfig.ExtraRecords resolve via libc (getent), and search
//     domains let bare names resolve, which requires tailscaled to
//     have plumbed MagicDNS routes and search domains into
//     systemd-resolved.
//   - A peer added by control resolves by FQDN and by short name,
//     and its IP reverse-resolves (PTR) to its name. The short name
//     resolves both via a search domain and asked of quad-100
//     verbatim, which is the half [TestBareNameNotHijackedByPeer]
//     requires to stay off when MagicDNS is disabled.
//   - A peer renamed by control resolves under its new name only:
//     the old name must stop resolving, and PTR must track the new
//     name. When a node is renamed in the admin console, the control
//     plane sends peers a single MapResponse delta: a PeersChanged
//     entry containing the full updated Node with the new Name, and
//     notably no new DNSConfig (MagicDNS records are computed
//     client-side from peer names). This test injects deltas of
//     exactly that shape. It reproduces tailscale/corp#45631, where
//     a renamed node's old name kept resolving.
//   - A peer removed by control stops resolving.
func TestMagicDNS(t *testing.T) {
	env := vmtest.New(t, vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"tailnet.test", "record"},
		Routes: map[string][]*dnstype.Resolver{
			"tailnet.test": nil,
			"record":       nil,
		},
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "extratest.record", Type: "A", Value: "1.2.3.4"},
		},
	}))
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404))
	env.Start()

	dt := &dnsTester{t: t, env: env, node: node}

	// ExtraRecords, by full name and via the "record" search domain.
	dt.wantResolves("extratest.record", "1.2.3.4")
	dt.wantResolves("extratest", "1.2.3.4")

	nodeKey := env.Status(node).Self.PublicKey
	cs := env.ControlServer()

	// Add a peer the way control does, as a PeersChanged delta
	// carrying the full node.
	peerAddr := netip.MustParsePrefix("100.64.7.7/32")
	peer := &tailcfg.Node{
		ID:                7777,
		StableID:          "peer1renamed",
		Name:              "renamee.tailnet.test.",
		User:              7777,
		Key:               key.NewNode().Public(),
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{peerAddr},
		AllowedIPs:        []netip.Prefix{peerAddr},
		Hostinfo:          (&tailcfg.Hostinfo{OS: "linux", Hostname: "renamee"}).View(),
		Cap:               tailcfg.CurrentCapabilityVersion,
		MachineAuthorized: true,
	}
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{peer},
	}) {
		t.Fatal("AddRawMapResponse(add peer): node not connected")
	}
	dt.wantResolves("renamee.tailnet.test", "100.64.7.7")
	dt.wantResolves("renamee", "100.64.7.7") // via search domain
	dt.wantResolves("100.64.7.7", "renamee.tailnet.test")
	// Also as a single label, which the search domain above hides:
	// getent passes "renamee.tailnet.test" to quad-100, not "renamee".
	// This is the enabled-MagicDNS counterpart of
	// [TestBareNameNotHijackedByPeer].
	dt.wantQueryResolves("renamee", "100.64.7.7")

	// Rename the peer, sending the same delta shape production
	// control sends: the full node again with only the Name changed.
	renamed := peer.Clone()
	renamed.Name = "renamed.tailnet.test."
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{renamed},
	}) {
		t.Fatal("AddRawMapResponse(rename peer): node not connected")
	}
	dt.wantResolves("renamed.tailnet.test", "100.64.7.7")
	dt.wantResolves("renamed", "100.64.7.7")
	dt.wantResolves("100.64.7.7", "renamed.tailnet.test")
	dt.wantNXDOMAIN("renamee.tailnet.test")
	dt.wantNXDOMAIN("renamee")

	// Remove the peer; its name must stop resolving.
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersRemoved: []tailcfg.NodeID{peer.ID},
	}) {
		t.Fatal("AddRawMapResponse(remove peer): node not connected")
	}
	dt.wantNXDOMAIN("renamed.tailnet.test")
}

// dnsTester asserts DNS state in a guest, retrying for a bit because
// tailscaled applies netmap and DNS config changes asynchronously.
// Lookups go through libc (getent) unless noted.
type dnsTester struct {
	t    *testing.T
	env  *vmtest.Env
	node *vmtest.Node
}

// wantResolves waits until name resolves and its answer contains want.
// With an IP address as name, getent does a reverse (PTR) lookup and
// want is the expected hostname. It flushes systemd-resolved's cache
// before each attempt so it tests tailscaled's resolver rather than a
// previously cached answer.
func (dt *dnsTester) wantResolves(name, want string) {
	dt.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		dt.env.SSHExec(dt.node, "resolvectl flush-caches")
		out, err := dt.env.SSHExec(dt.node, "getent hosts "+name)
		if err != nil {
			return fmt.Errorf("getent hosts %s: %v (%s)", name, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("getent hosts %s = %q, want it to contain %q", name, strings.TrimSpace(out), want)
		}
		return nil
	}); err != nil {
		out, _ := dt.env.SSHExec(dt.node, "resolvectl status; cat /etc/resolv.conf")
		dt.t.Fatalf("%v\nresolver state:\n%s", err, out)
	}
}

// wantQueryResolves is [dnsTester.wantResolves] via "tailscale dns
// query", which asks quad-100 for exactly the name given. Use it when
// the name must stay unqualified: getent would let a search domain
// complete it and resolve a different name.
func (dt *dnsTester) wantQueryResolves(name, want string) {
	dt.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := dt.env.SSHExec(dt.node, "tailscale dns query "+name)
		if err != nil {
			return fmt.Errorf("tailscale dns query %s: %v (%s)", name, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("tailscale dns query %s = %q, want it to contain %q", name, strings.TrimSpace(out), want)
		}
		return nil
	}); err != nil {
		out, _ := dt.env.SSHExec(dt.node, "resolvectl status; cat /etc/resolv.conf")
		dt.t.Fatalf("%v\nresolver state:\n%s", err, out)
	}
}

// wantNXDOMAIN waits until name no longer resolves. It flushes
// systemd-resolved's cache before each attempt so it tests
// tailscaled's resolver rather than a previously cached answer.
func (dt *dnsTester) wantNXDOMAIN(name string) {
	dt.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		dt.env.SSHExec(dt.node, "resolvectl flush-caches")
		out, err := dt.env.SSHExec(dt.node, "getent hosts "+name)
		if err == nil {
			return fmt.Errorf("%s still resolves: %q", name, strings.TrimSpace(out))
		}
		return nil
	}); err != nil {
		dt.t.Fatal(err)
	}
}

// TestSplitDNS runs the split-DNS checks against the systemd-resolved backend,
// which Ubuntu uses by default.
func TestSplitDNS(t *testing.T) {
	testSplitDNS(t, vmtest.DNSDefault, "systemd-resolved")
}

// TestSplitDNSDirect runs the same checks against the "direct" backend, which
// tailscaled uses when it has to write /etc/resolv.conf itself.
func TestSplitDNSDirect(t *testing.T) {
	testSplitDNS(t, vmtest.DNSDirect, "direct")
}

// testSplitDNS checks that a node resolves each kind of name via the right
// resolver: see the checks table below, which has a row per kind. The mixed
// routes leave no single resolver set to hand the OS, so quad-100 does the
// forwarding; [TestSplitDNSOSForwarded] covers the other arrangement.
//
// dnsMode picks the DNS backend; wantBackend is asserted so a pass can't come
// from the wrong one.
func testSplitDNS(t *testing.T, dnsMode vmtest.DNSMode, wantBackend string) {
	t.Helper()

	// vnet's second DNS server is the *only* thing serving fwdName, so an
	// answer means the query was forwarded there.
	const (
		fwdDomain = vnet.SplitDNSDomain
		fwdName   = vnet.SplitDNSName
		fwdIP     = vnet.SplitDNSAddr
	)
	fwdResolver := vnet.FakeSplitDNSIPv4()

	// A route with no resolvers, plus an extra record for a name in it. localIP
	// is never connected to, only resolved; it's outside the 100.64.x.y block
	// testcontrol assigns nodes, so an answer can only have come from the extra
	// record.
	const (
		localDomain = "local.example"
		localName   = "host." + localDomain
		localIP     = "100.99.99.99"
	)

	// The peer's node name becomes its guest hostname, and control appends the
	// tailnet's MagicDNS domain, so its name is predictable.
	const (
		magicDNSDomain = "tailnet.test"
		peerNodeName   = "peer"
		wantPeerName   = peerNodeName + "." + magicDNSDomain
	)

	env := vmtest.New(t,
		vmtest.SameTailnetUser(), // so the peer is visible and its MagicDNS name resolves
		vmtest.ControlDNS(magicDNSDomain, &tailcfg.DNSConfig{
			Proxied: true, // turn on MagicDNS, so the peer's tailnet name resolves
			// Search domains, so the bare name "host" also resolves as
			// host.local.example.
			Domains: []string{localDomain},
			// These routes don't share a resolver set, so quad-100 does the
			// forwarding. Proxied also adds a nil-resolver route per MagicDNS
			// root domain, so the sets differ regardless.
			Routes: map[string][]*dnstype.Resolver{
				fwdDomain:   {{Addr: fwdResolver.String()}}, // forward here
				localDomain: nil,                            // answer locally
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: localName, Type: "A", Value: localIP}, // the local answer
			},
		}))

	// Two nodes: client is the one we run lookups on; peer exists only so
	// there's a tailnet name to look up. Nothing runs on peer.
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	client := env.AddNode("client", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.WithDNSMode(dnsMode))
	peer := env.AddNode(peerNodeName, lan,
		vmtest.OS(vmtest.Ubuntu2404))

	env.Start()

	// The peer's lookup and expected answer. Checking the name against what
	// control should have assigned, rather than trusting whatever it reports,
	// means a MagicDNS naming change fails here instead of quietly resolving
	// some other name and passing.
	peerSt := env.Status(peer)
	peerName := strings.TrimSuffix(peerSt.Self.DNSName, ".")
	if peerName != wantPeerName {
		t.Fatalf("peer DNSName = %q, want %q", peerName, wantPeerName)
	}
	var peerIP string // IPv4, since the lookups below ask for A records only
	for _, a := range peerSt.Self.TailscaleIPs {
		if a.Is4() {
			peerIP = a.String()
			break
		}
	}
	if peerIP == "" {
		t.Fatalf("peer has no IPv4 TailscaleIP in status (got %v)", peerSt.Self.TailscaleIPs)
	}

	env.AssertDNSBackend(client, wantBackend)

	// The OS was pointed at quad-100 and *not* handed the split resolver, i.e.
	// quad-100 is doing the forwarding.
	assertResolverState(t, env, client,
		[]string{"100.100.100.100"},
		[]string{fwdResolver.String()})

	// "getent ahostsv4" (A only) rather than "getent hosts":
	// dualstack-web.example.com has both A and AAAA, and "hosts" can return
	// either family.
	checks := []struct {
		name string // what to look up on the client
		want string // the answer proving it was resolved by the right thing
		what string // which of the four cases this is, for failure messages
	}{
		{
			name: fwdName,
			want: fwdIP,
			what: "forwarded: routed domain went to its designated resolver",
		},
		{
			name: localName,
			want: localIP,
			what: "local: empty-resolver route answered by quad-100",
		},
		// Same answer, but looked up as a bare name to check the search domain.
		{
			name: "host",
			want: localIP,
			what: "local: bare name completed by the " + localDomain + " search domain",
		},
		// quad-100 answers tailnet names from the netmap.
		{
			name: peerName,
			want: peerIP,
			what: "magicdns: peer's tailnet name resolved to its tailnet IP",
		},
		// No route covers this, so it must still reach the normal DNS server
		// (here vnet's default one, standing in for the internet).
		{
			name: "dualstack-web.example.com",
			want: "5.0.0.100",
			what: "default: unrouted name still resolved normally",
		},
	}

	for _, c := range checks {
		// Retry: tailscaled applies DNS config to the OS resolver
		// asynchronously after coming up.
		if err := tstest.WaitFor(30*time.Second, func() error {
			out, err := env.SSHExec(client, "getent ahostsv4 "+c.name)
			if err != nil {
				return fmt.Errorf("getent ahostsv4 %s (%s): %v (%s)", c.name, c.what, err, strings.TrimSpace(out))
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("getent ahostsv4 %s (%s) = %q, want it to contain %s", c.name, c.what, strings.TrimSpace(out), c.want)
			}
			return nil
		}); err != nil {
			out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf")
			t.Fatalf("%v\nclient resolver state:\n%s", err, out)
		}
	}
}

// TestSplitDNSOSForwarded checks the other way tailscaled can implement a routed
// domain: handing the OS resolver the domain's resolver directly, with quad-100
// out of the query path. It does that only when every route shares one resolver
// set, hence the single route and no MagicDNS here.
//
// There is no "direct" variant. That backend only rewrites resolv.conf, so it
// reports SupportsSplitDNS() == false and always forwards via quad-100, which
// [TestSplitDNSDirect] covers.
func TestSplitDNSOSForwarded(t *testing.T) {
	// Only vnet's second DNS server answers fwdName, so an answer means the query
	// got there.
	const (
		fwdDomain = vnet.SplitDNSDomain
		fwdName   = vnet.SplitDNSName
		fwdIP     = vnet.SplitDNSAddr
	)
	fwdResolver := vnet.FakeSplitDNSIPv4()

	// systemd-resolved sends match-domain queries out the link it programmed them
	// on -- the Tailscale interface -- so the split resolver has to be reachable
	// over the tailnet, as it would be in a real deployment. Advertise a route
	// covering it from a second node.
	fwdResolverRoute := netip.PrefixFrom(fwdResolver, 32).String()

	env := vmtest.New(t,
		vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			Routes: map[string][]*dnstype.Resolver{
				fwdDomain: {{Addr: fwdResolver.String()}},
			},
		}))

	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	client := env.AddNode("client", lan,
		vmtest.OS(vmtest.Ubuntu2404))
	// This node exists only to make fwdResolver routable over the tailnet; no
	// DNS server runs on it. vnet answers the queries once they're on the wire.
	resolverRouter := env.AddNode("resolver-router", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.AdvertiseRoutes(fwdResolverRoute))

	env.Start()

	// ApproveRoutes also turns on accept-routes on the other nodes, so the
	// client installs the route to fwdResolver.
	env.ApproveRoutes(resolverRouter, fwdResolverRoute)

	env.AssertDNSBackend(client, "systemd-resolved")

	// This is what separates this test from [testSplitDNS]: systemd-resolved holds
	// the split resolver itself and quad-100 is absent. The lookup below would
	// pass either way.
	assertResolverState(t, env, client,
		[]string{fwdResolver.String(), "~" + fwdDomain},
		[]string{"100.100.100.100"})

	// The route from resolverRouter is what makes the lookup below work: with the
	// split resolver on tailscale0, resolved sends the query out that link, and
	// without a route there it times out rather than falling back to the LAN.
	// Assert the route landed, so a lookup failure points here instead of at the
	// resolver config. Retried because the client installs it asynchronously
	// after ApproveRoutes.
	if err := tstest.WaitFor(30*time.Second, func() error {
		cmd := "ip route get " + fwdResolver.String()
		out, err := env.SSHExec(client, cmd)
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, "dev tailscale0") {
			return fmt.Errorf("%s = %q, want it to go via tailscale0", cmd, strings.TrimSpace(out))
		}
		return nil
	}); err != nil {
		out, _ := env.SSHExec(client, "ip route; tailscale status")
		t.Fatalf("%v\nclient routes:\n%s", err, out)
	}

	// And it works end to end.
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(client, "getent ahostsv4 "+fwdName)
		if err != nil {
			return fmt.Errorf("getent ahostsv4 %s: %v (%s)", fwdName, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, fwdIP) {
			return fmt.Errorf("getent ahostsv4 %s = %q, want it to contain %s", fwdName, strings.TrimSpace(out), fwdIP)
		}
		return nil
	}); err != nil {
		out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf; ip route")
		t.Fatalf("%v\nclient resolver state:\n%s", err, out)
	}
}

// TestSplitDNSNoMagicDNS covers split DNS on a tailnet with MagicDNS turned off,
// the one combination the tests above leave out. [testSplitDNS] has mixed
// resolver sets but MagicDNS on; [TestSplitDNSOSForwarded] has MagicDNS off but
// a single resolver set. Both conditions together take a distinct path through
// compileConfig: with no MagicDNS route to scope to, tailscaled reads the OS's
// base resolver config to use as quad-100's fallback.
//
// systemd-resolved has no base config to give -- it answers
// ErrGetBaseConfigNotSupported -- so this exercises what tailscaled does when
// that read fails. The lookups matter less than the resolver state assertion:
// if applying the config fails, tailscaled leaves whatever it installed last in
// place, so the failure shows up as stale OS resolver state rather than as an
// error the guest can see.
func TestSplitDNSNoMagicDNS(t *testing.T) {
	// Only vnet's second DNS server answers fwdName, so an answer means the
	// query was forwarded there.
	const (
		fwdDomain = vnet.SplitDNSDomain
		fwdName   = vnet.SplitDNSName
		fwdIP     = vnet.SplitDNSAddr
	)
	fwdResolver := vnet.FakeSplitDNSIPv4()

	// A second route with a different resolver, so no single resolver set can
	// be handed to the OS. Nothing is ever looked up in it; with MagicDNS off
	// there is no nil-resolver root domain route to force the split, so this
	// route is what does it.
	const otherDomain = "other.example"
	otherResolver := "10.0.0.2"

	// An extra record, and a search domain so the bare name resolves too.
	// localIP is outside the 100.64.x.y block testcontrol assigns nodes, so an
	// answer can only have come from the extra record.
	const (
		localDomain = "local.example"
		localName   = "host." + localDomain
		localIP     = "100.99.99.99"
	)

	env := vmtest.New(t,
		vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			// Proxied is deliberately absent: MagicDNS off. That is what
			// separates this test from [testSplitDNS].
			Domains: []string{localDomain},
			Routes: map[string][]*dnstype.Resolver{
				fwdDomain:   {{Addr: fwdResolver.String()}},
				otherDomain: {{Addr: otherResolver}},
				localDomain: nil,
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: localName, Type: "A", Value: localIP},
			},
		}))

	client := env.AddNode("client",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404))

	env.Start()

	env.AssertDNSBackend(client, "systemd-resolved")

	// The OS points at quad-100 for the routed domains and was not handed the
	// split resolvers. A failed config apply leaves stale state here, which is
	// the symptom this test is really after.
	//
	// localDomain has no "~": it's a search domain (see Domains above), which
	// resolved lists bare, unlike the routing-only domains.
	assertResolverState(t, env, client,
		[]string{"100.100.100.100", "~" + fwdDomain, "~" + otherDomain, localDomain},
		[]string{fwdResolver.String(), otherResolver})

	checks := []struct {
		name string // what to look up on the client
		want string // the answer proving the right resolver handled it
		what string // for failure messages
	}{
		{
			name: fwdName,
			want: fwdIP,
			what: "forwarded: routed domain went to its designated resolver",
		},
		{
			name: localName,
			want: localIP,
			what: "local: empty-resolver route answered by quad-100",
		},
		{
			name: "host",
			want: localIP,
			what: "local: bare name completed by the " + localDomain + " search domain",
		},
		{
			name: "dualstack-web.example.com",
			want: "5.0.0.100",
			what: "default: unrouted name still resolved normally",
		},
	}

	for _, c := range checks {
		// Retry: tailscaled applies DNS config to the OS resolver
		// asynchronously after coming up.
		if err := tstest.WaitFor(30*time.Second, func() error {
			out, err := env.SSHExec(client, "getent ahostsv4 "+c.name)
			if err != nil {
				return fmt.Errorf("getent ahostsv4 %s (%s): %v (%s)", c.name, c.what, err, strings.TrimSpace(out))
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("getent ahostsv4 %s (%s) = %q, want it to contain %s", c.name, c.what, strings.TrimSpace(out), c.want)
			}
			return nil
		}); err != nil {
			out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf")
			t.Fatalf("%v\nclient resolver state:\n%s", err, out)
		}
	}
}

// assertResolverState fails the test unless the node's OS resolver state has
// every string in want and none in notWant, retrying while tailscaled applies
// its config asynchronously. notWant matters because the two split-DNS
// arrangements answer queries identically: the resolver that is *absent*
// identifies which one ran.
//
// It reads both resolvectl and resolv.conf because the backends record state in
// different places: systemd-resolved keeps servers and domains per-link, with
// resolv.conf just the 127.0.0.53 stub, while the direct backend writes
// resolv.conf itself and leaves resolved masked.
//
// Each want and notWant is matched as a whitespace-separated token, so pass
// exactly what appears in the output: a bare resolver address, or a routing-only
// ("match") domain with resolvectl's "~" prefix and no trailing dot. The
// resolvectl queries are scoped to tailscale0, so a match can't come from
// another link.
func assertResolverState(t *testing.T, env *vmtest.Env, n *vmtest.Node, want, notWant []string) {
	t.Helper()
	// Keep resolvectl's stderr: it's how resolved being absent (expected under
	// the direct backend) or broken (not) shows up in the failure dump.
	const cmd = "resolvectl dns tailscale0 2>&1; resolvectl domain tailscale0 2>&1; cat /etc/resolv.conf 2>&1"
	var last string
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		last = out
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		got := strings.Fields(out)
		for _, w := range want {
			if !slices.Contains(got, w) {
				return fmt.Errorf("resolver state is missing %q", w)
			}
		}
		for _, w := range notWant {
			if slices.Contains(got, w) {
				return fmt.Errorf("resolver state unexpectedly has %q", w)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%v\nwant all of %q and none of %q in resolver state:\n%s", err, want, notWant, last)
	}
}

// TestBareNameNotHijackedByPeer checks that a bare, unqualified name owned by
// the tailnet's global nameserver still reaches that nameserver when a tailnet
// device shares the name. With MagicDNS off only suffixed names should be
// answered locally, but quad-100 answered the bare name itself. Issue 20789.
//
// The lookup uses "tailscale dns query", which asks for exactly the name given:
// getent would let a search domain complete it and pass on a different name.
func TestBareNameNotHijackedByPeer(t *testing.T) {
	// Only vnet's second DNS server answers this name, so an answer proves the
	// query was forwarded. Its address is outside the 100.64.x.y block
	// testcontrol assigns nodes, so it can't be mistaken for a Tailscale IP.
	const (
		upstreamName = vnet.SplitDNSBareName
		upstreamIP   = vnet.SplitDNSBareAddr
	)

	env := vmtest.New(t,
		vmtest.SameTailnetUser(), // so the colliding peer is visible in the netmap
		vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			// No Proxied: MagicDNS off. No Domains: nothing can complete a bare
			// name into something else. Resolvers is the tailnet's global
			// nameserver, which owns upstreamName.
			Resolvers: []*dnstype.Resolver{{Addr: vnet.FakeSplitDNSIPv4().String()}},
		}))

	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	client := env.AddNode("client", lan, vmtest.OS(vmtest.Ubuntu2404))
	// The collision is the whole test: this node's MagicDNS name matches the
	// upstream record. Nothing runs on it.
	peer := env.AddNode(upstreamName, lan, vmtest.OS(vmtest.Ubuntu2404))

	env.Start()

	// A mangled or renamed peer would make the lookup below pass without
	// exercising the collision at all.
	peerSt := env.Status(peer)
	if want := upstreamName + ".tailnet.test"; strings.TrimSuffix(peerSt.Self.DNSName, ".") != want {
		t.Fatalf("peer DNSName = %q, want %q", peerSt.Self.DNSName, want)
	}
	// What a hijacked answer would look like, so the check below can name it.
	var peerIP string // IPv4: the query below asks for an A record
	for _, a := range peerSt.Self.TailscaleIPs {
		if a.Is4() {
			peerIP = a.String()
			break
		}
	}
	if peerIP == "" {
		t.Fatalf("peer has no IPv4 TailscaleIP in status (got %v)", peerSt.Self.TailscaleIPs)
	}

	// Retried because tailscaled applies the DNS config asynchronously after
	// coming up.
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(client, "tailscale dns query "+upstreamName)
		if err != nil {
			return fmt.Errorf("tailscale dns query %s: %v (%s)", upstreamName, err, strings.TrimSpace(out))
		}
		// Checked first: the failure is a well-formed A record for the wrong
		// address, which "missing upstreamIP" alone wouldn't convey.
		if strings.Contains(out, peerIP) {
			return fmt.Errorf("query for %s was answered with the peer's Tailscale IP %s, "+
				"want it forwarded to the global nameserver:\n%s", upstreamName, peerIP, strings.TrimSpace(out))
		}
		if !strings.Contains(out, upstreamIP) {
			return fmt.Errorf("query for %s = %q, want it to contain %s", upstreamName, strings.TrimSpace(out), upstreamIP)
		}
		return nil
	}); err != nil {
		out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf")
		t.Fatalf("%v\nclient resolver state:\n%s", err, out)
	}
}
