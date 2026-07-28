// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
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
//     and its IP reverse-resolves (PTR) to its name.
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

// dnsTester asserts DNS state in a guest via libc lookups (getent),
// retrying for a bit because tailscaled applies netmap and DNS config
// changes asynchronously.
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
