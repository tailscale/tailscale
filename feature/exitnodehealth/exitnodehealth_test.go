// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package exitnodehealth

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"tailscale.com/control/controlclient"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

func extOf(t *testing.T, b *ipnlocal.LocalBackend) *extension {
	t.Helper()
	c := qt.New(t)

	e, ok := ipnlocal.GetExt[*extension](b)
	c.Assert(ok, qt.IsTrue, qt.Commentf("exit node health extension not registered"))
	return e
}

func contextFor(b *ipnlocal.LocalBackend) healthContext {
	e, _ := ipnlocal.GetExt[*extension](b)
	e.mu.Lock()
	configured := e.networkConfigured
	e.mu.Unlock()
	c := healthContext{State: b.State(), NetworkConfigured: configured, Prefs: b.Prefs()}
	for _, peer := range b.ForTest().Peers() {
		if peer.StableID() == c.Prefs.ExitNodeID() {
			c.Peer = peer
			break
		}
	}
	return c
}

// exitNodeHealthTestNetMap returns a netmap with two peers: "exit1"
// ("my-gateway"), which offers exit routes, and "plain1" ("laptop"), which does
// not.
func exitNodeHealthTestNetMap() *netmap.NetworkMap {
	hi := (&tailcfg.Hostinfo{}).View()
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:                10,
			StableID:          "self",
			Key:               key.NewNode().Public(),
			Name:              "self.example.ts.net.",
			Hostinfo:          hi,
			Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
			MachineAuthorized: true,
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:                1,
				StableID:          "exit1",
				Key:               key.NewNode().Public(),
				DiscoKey:          key.NewDisco().Public(),
				Name:              "my-gateway.example.ts.net.",
				Hostinfo:          hi,
				Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
				AllowedIPs:        append([]netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, tsaddr.ExitRoutes()...),
				MachineAuthorized: true,
				HomeDERP:          1,
			}).View(),
			(&tailcfg.Node{
				ID:                2,
				StableID:          "plain1",
				Key:               key.NewNode().Public(),
				DiscoKey:          key.NewDisco().Public(),
				Name:              "laptop.example.ts.net.",
				Hostinfo:          hi,
				Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
				AllowedIPs:        []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
				MachineAuthorized: true,
				HomeDERP:          1,
			}).View(),
		},
	}
	for i, view := range nm.Peers {
		peer := view.AsStruct()
		peer.InitDisplayNames("example.ts.net")
		nm.Peers[i] = peer.View()
	}
	return nm
}

// newExitNodeHealthTestBackend returns a backend with
// [exitNodeHealthTestNetMap] installed, ready to run
// auth reconfiguration. If sys is nil, a default one is used.
func newExitNodeHealthTestBackend(t *testing.T, sys *tsd.System) *ipnlocal.LocalBackend {
	t.Helper()
	c := qt.New(t)

	if !buildfeatures.HasHealth || !buildfeatures.HasUseExitNode {
		t.Skip("exit node health dependencies omitted")
	}

	var b *ipnlocal.LocalBackend
	if sys == nil {
		b = ipnlocaltest.NewBackend(t)
	} else {
		b = ipnlocaltest.NewBackendWithSys(t, sys)
	}

	b.ForTest().InitExtensions()
	err := b.ForTest().SetPersist(&persist.Persist{})
	c.Assert(err, qt.IsNil)

	b.ForTest().ApplyNetMap(exitNodeHealthTestNetMap())
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true})
	b.ForTest().SetState(ipn.Running)
	return b
}

// TestExitNodeUnavailableWarning tests that selecting an exit node that can't
// carry internet traffic — because it left the tailnet, because it isn't
// offering exit node service, or because none has been chosen yet — raises
// [exitNodeUnavailableWarnable] rather than silently blackholing traffic.
func TestExitNodeUnavailableWarning(t *testing.T) {
	tests := []struct {
		name       string
		prefs      *ipn.Prefs
		wantReason ExitNodeHealthVerdict
		wantName   string
	}{
		{
			name:       "no-exit-node",
			prefs:      &ipn.Prefs{WantRunning: true},
			wantReason: ExitNodeOK,
		},
		{
			name:       "good-exit-node-by-id",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"},
			wantReason: ExitNodeOK,
		},
		{
			name:       "good-exit-node-by-ip",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeIP: netip.MustParseAddr("100.64.0.2")},
			wantReason: ExitNodeOK,
		},
		{
			name:       "id-not-in-tailnet",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeID: "no-such-node"},
			wantReason: ExitNodeNotInTailnet,
			wantName:   "no-such-node",
		},
		{
			name:       "ip-never-resolved",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeIP: netip.MustParseAddr("100.64.9.9")},
			wantReason: ExitNodeNotInTailnet,
			wantName:   "100.64.9.9",
		},
		{
			name:       "peer-offers-no-exit-routes",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeID: "plain1"},
			wantReason: ExitNodeNoExitRoutes,
			wantName:   "laptop",
		},
		{
			name:       "auto-exit-node-not-yet-selected",
			prefs:      &ipn.Prefs{WantRunning: true, ExitNodeID: "auto:any"},
			wantReason: ExitNodeNotYetSelected,
		},
		{
			// Tailscale is stopped, so we're not dropping anything and
			// health.IPNStateWarnable is the relevant warning.
			name:       "not-running",
			prefs:      &ipn.Prefs{WantRunning: false, ExitNodeID: "no-such-node"},
			wantReason: ExitNodeOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newExitNodeHealthTestBackend(t, nil)
			b.ForTest().SetPrefs(tt.prefs)
			b.ForTest().AuthReconfig()

			extOf(t, b).mu.Lock()
			gotReason := extOf(t, b).reason
			extOf(t, b).mu.Unlock()
			if gotReason != tt.wantReason {
				t.Errorf("reason = %q, want %q", gotReason, tt.wantReason)
			}

			wantUnhealthy := tt.wantReason != ExitNodeOK
			if got := b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable); got != wantUnhealthy {
				t.Errorf("IsUnhealthy = %v, want %v", got, wantUnhealthy)
			}
			if !wantUnhealthy {
				return
			}

			_, gotName := evaluateExitNodeStatus(contextFor(b))
			args := extOf(t, b).warnableArgs(gotReason, gotName, false)
			if gotName != tt.wantName {
				t.Errorf("exit node name = %q, want %q", gotName, tt.wantName)
			}
			if got := args[ArgExitNodePolicyForced]; got != "" {
				t.Errorf("ArgExitNodePolicyForced = %q, want empty without a policy", got)
			}
		})
	}
}

// TestExitNodeUnavailableWarningNamesDepartedNode tests that once the selected
// exit node leaves the tailnet, the warning still names it rather than falling
// back to its stable ID.
func TestExitNodeUnavailableWarningNamesDepartedNode(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	nm := exitNodeHealthTestNetMap()
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	b.ForTest().AuthReconfig()
	if b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
		t.Fatal("warning set while the exit node is present and offering exit routes")
	}

	// The exit node leaves the tailnet.
	nm.Peers = nm.Peers[1:]
	b.ForTest().ApplyNetMap(nm)
	b.ForTest().AuthReconfig()
	if !b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
		t.Fatal("warning not set after the exit node left the tailnet")
	}

	reason, _ := evaluateExitNodeStatus(contextFor(b))
	extOf(t, b).mu.Lock()
	args := extOf(t, b).warnableArgs(reason, extOf(t, b).lastKnownName, false)
	extOf(t, b).mu.Unlock()
	if reason != ExitNodeNotInTailnet {
		t.Errorf("reason = %q, want %q", reason, ExitNodeNotInTailnet)
	}
	if got := args[ArgExitNodeName]; got != "my-gateway" {
		t.Errorf("ArgExitNodeName = %q, want %q", got, "my-my-gateway")
	}

	// And it clears once the exit node comes back.
	b.ForTest().ApplyNetMap(exitNodeHealthTestNetMap())
	b.ForTest().AuthReconfig()
	if b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
		t.Fatal("warning not cleared after the exit node returned")
	}
}

// TestExitNodeUnavailableWarningOnNetmapDelta tests the scenario the warning
// exists for: the selected exit node is removed from the tailnet via an
// incremental netmap update, which is the path a real client takes. The
// warning must be raised without anyone calling authReconfig by hand.
func TestExitNodeUnavailableWarningOnNetmapDelta(t *testing.T) {
	c := qt.New(t)

	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	b.ForTest().AuthReconfig()
	isUnhealthy := b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable)
	c.Assert(isUnhealthy, qt.IsFalse, qt.Commentf("warning set while the exit node is present and offering exit routes"))
	// Control removes the exit node (node ID 1) from the tailnet.
	muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
		PeersRemoved: []tailcfg.NodeID{1},
	}, time.Unix(123, 0))

	c.Assert(ok, qt.IsTrue, qt.Commentf("netmap.MutationsFromMapResponse failed"))
	c.Assert(b.UpdateNetmapDelta(muts), qt.IsTrue, qt.Commentf("UpdateNetmapDelta returned false"))
	c.Assert(b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable), qt.IsTrue, qt.Commentf("warning not set after the exit node was removed by a netmap delta"))

	extOf(t, b).mu.Lock()
	gotReason := extOf(t, b).reason
	extOf(t, b).mu.Unlock()
	if gotReason != ExitNodeNotInTailnet {
		t.Errorf("reason = %q, want %q", gotReason, ExitNodeNotInTailnet)
	}
}

// TestExitNodeUnavailableWarningPolicyForced tests that an exit node mandated
// by the ExitNodeID policy setting produces a warning telling the user to
// contact their administrator, since they can't change the selection.
func TestExitNodeUnavailableWarningPolicyForced(t *testing.T) {
	if !buildfeatures.HasSystemPolicy {
		t.Skip("system policy omitted")
	}

	sys := tsd.NewSystem()
	sys.PolicyClient.Set(policytest.Config{pkey.ExitNodeID: "no-such-node"})
	b := newExitNodeHealthTestBackend(t, sys)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true})
	b.ForTest().AuthReconfig()

	if !b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
		t.Fatal("warning not set for a policy-forced exit node that isn't in the tailnet")
	}
	if got := b.Prefs().ExitNodeID(); got != "no-such-node" {
		t.Fatalf("ExitNodeID = %q; policy did not take effect", got)
	}
	reason, name := evaluateExitNodeStatus(contextFor(b))
	args := extOf(t, b).warnableArgs(reason, name, false)

	if got := args[ArgExitNodePolicyForced]; got != "true" {
		t.Errorf("ArgExitNodePolicyForced = %q, want %q", got, "true")
	}
	if text := warnableText(args); !strings.Contains(text, "network administrator") {
		t.Errorf("text = %q; want it to mention the network administrator", text)
	}
}

func TestExitNodeUnavailableText(t *testing.T) {
	tests := []struct {
		name string
		args health.Args
		want string
	}{
		{
			name: "not-in-tailnet",
			args: health.Args{
				ArgExitNodeReason: string(ExitNodeNotInTailnet),
				ArgExitNodeName:   "my-vps",
			},
			want: `The selected exit node "my-vps" is no longer available on your tailnet. ` +
				"Internet traffic is being dropped to avoid leaking it to the local network. " +
				"Select a different exit node, or turn off exit node use.",
		},
		{
			name: "no-exit-routes",
			args: health.Args{
				ArgExitNodeReason: string(ExitNodeNoExitRoutes),
				ArgExitNodeName:   "laptop",
			},
			want: `The selected exit node "laptop" is not offering exit node service. ` +
				"Internet traffic is being dropped to avoid leaking it to the local network. " +
				"Select a different exit node, or turn off exit node use.",
		},
		{
			name: "not-yet-selected",
			args: health.Args{ArgExitNodeReason: string(ExitNodeNotYetSelected)},
			want: "An exit node is required by policy, but no exit node is available to use. " +
				"Internet traffic is being dropped to avoid leaking it to the local network. " +
				"Select a different exit node, or turn off exit node use.",
		},
		{
			name: "policy-forced",
			args: health.Args{
				ArgExitNodeReason:       string(ExitNodeNotInTailnet),
				ArgExitNodeName:         "corp-exit",
				ArgExitNodePolicyForced: "true",
			},
			want: `The selected exit node "corp-exit" is no longer available on your tailnet. ` +
				"Internet traffic is being dropped to avoid leaking it to the local network. " +
				"This exit node is required by your network administrator; contact them for help.",
		},
		{
			name: "unnamed",
			args: health.Args{ArgExitNodeReason: string(ExitNodeNotInTailnet)},
			want: "The selected exit node is no longer available on your tailnet. " +
				"Internet traffic is being dropped to avoid leaking it to the local network. " +
				"Select a different exit node, or turn off exit node use.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := warnableText(tt.args); got != tt.want {
				t.Errorf("exitNodeUnavailableText() =\n %q\nwant\n %q", got, tt.want)
			}
		})
	}
}

func TestWarningClears(t *testing.T) {
	tests := []struct {
		name string
		stop bool
	}{
		{name: "no-netmap"},
		{name: "stopped", stop: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newExitNodeHealthTestBackend(t, nil)
			b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "missing"})
			b.ForTest().AuthReconfig()
			if !b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
				t.Fatal("warning not raised")
			}

			if tt.stop {
				b.ForTest().SetPrefs(&ipn.Prefs{ExitNodeID: "missing"})
			} else {
				b.ForTest().ApplyNetMap(nil)
			}
			b.ForTest().AuthReconfig()
			if b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable) {
				t.Fatal("warning not cleared")
			}
		})
	}
}

func TestPolicyArgs(t *testing.T) {
	tests := []struct {
		name       string
		policyKey  pkey.Key
		overridden bool
	}{
		{name: "exit-node-id", policyKey: pkey.ExitNodeID},
		{name: "exit-node-id-overridden", policyKey: pkey.ExitNodeID, overridden: true},
		{name: "exit-node-ip", policyKey: pkey.ExitNodeIP},
		{name: "exit-node-ip-overridden", policyKey: pkey.ExitNodeIP, overridden: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &extension{polc: policytest.Config{tt.policyKey: "configured"}}
			args := e.warnableArgs(ExitNodeNotInTailnet, "missing", tt.overridden)

			want := buildfeatures.HasSystemPolicy && !tt.overridden
			if got := args[ArgExitNodePolicyForced] == "true"; got != want {
				t.Errorf("policy forced = %v, want %v", got, want)
			}
		})
	}
}

func TestLogsOnlyTransitions(t *testing.T) {
	var logs []string
	e := &extension{polc: policytest.Config{}, logf: func(format string, args ...any) {
		logs = append(logs, format)
	}}
	// A nil health tracker supports warning updates as no-ops.
	c := healthContext{State: ipn.Running, NetworkConfigured: true, Prefs: (&ipn.Prefs{WantRunning: true, ExitNodeID: "missing"}).View()}
	e.updateWarnableLocked(c)
	e.updateWarnableLocked(c)
	c.NetworkConfigured = false
	e.updateWarnableLocked(c)
	e.updateWarnableLocked(c)
	if len(logs) != 2 {
		t.Errorf("got %d logs, want two transitions", len(logs))
	}
}

func TestMissingDependencies(t *testing.T) {
	if buildfeatures.HasHealth && buildfeatures.HasUseExitNode {
		t.Skip("all dependencies included")
	}
	// Skipping must happen before the constructor accesses the backend.
	if _, err := newExtension(t.Logf, nil); !errors.Is(err, ipnext.SkipExtension) {
		t.Fatalf("newExtension = %v, want SkipExtension", err)
	}
}

func wantReason(t *testing.T, b *ipnlocal.LocalBackend, want ExitNodeHealthVerdict) {
	t.Helper()
	e := extOf(t, b)
	e.mu.Lock()
	got := e.reason
	e.mu.Unlock()
	if got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if got := b.HealthTracker().IsUnhealthy(exitNodeUnavailableWarnable); got != (want != ExitNodeOK) {
		t.Errorf("warning raised = %v, want %v", got, want != ExitNodeOK)
	}
}

func TestStateChangesWithoutReconfig(t *testing.T) {
	tests := []struct {
		name  string
		state ipn.State
	}{
		{name: "no-state", state: ipn.NoState},
		{name: "stopped", state: ipn.Stopped},
		{name: "needs-login", state: ipn.NeedsLogin},
		{name: "needs-machine-auth", state: ipn.NeedsMachineAuth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newExitNodeHealthTestBackend(t, nil)
			b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "missing"})
			wantReason(t, b, ExitNodeNotInTailnet)

			b.ForTest().SetState(tt.state)
			wantReason(t, b, ExitNodeOK)

			// WantRunning and the selected exit node have not changed.
			b.ForTest().SetState(ipn.Running)
			wantReason(t, b, ExitNodeNotInTailnet)
		})
	}
}

func TestFullNetmapChangesWithoutReconfig(t *testing.T) {
	tests := []struct {
		name       string
		netmap     func() *netmap.NetworkMap
		wantReason ExitNodeHealthVerdict
	}{
		{
			name: "exit-node-offline",
			netmap: func() *netmap.NetworkMap {
				nm := exitNodeHealthTestNetMap()
				peer := nm.Peers[0].AsStruct()
				peer.Online = new(false)
				nm.Peers[0] = peer.View()
				return nm
			},
			wantReason: ExitNodeOK,
		},
		{
			name: "exit-node-without-exit-routes",
			netmap: func() *netmap.NetworkMap {
				nm := exitNodeHealthTestNetMap()
				peer := nm.Peers[0].AsStruct()
				peer.AllowedIPs = nil
				nm.Peers[0] = peer.View()
				return nm
			},
			wantReason: ExitNodeNoExitRoutes,
		},
		{
			name:       "no-netmap",
			netmap:     func() *netmap.NetworkMap { return nil },
			wantReason: ExitNodeOK,
		},
	}
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b.ForTest().ApplyNetMap(tt.netmap())
			wantReason(t, b, tt.wantReason)
		})
	}
}

func TestProfileChangeClearsWarningAndName(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	nm := exitNodeHealthTestNetMap()
	nm.Peers = nm.Peers[1:]
	b.ForTest().ApplyNetMap(nm)
	wantReason(t, b, ExitNodeNotInTailnet)
	e := extOf(t, b)
	e.mu.Lock()
	name := e.lastKnownName
	e.mu.Unlock()
	if name != "my-gateway" {
		t.Fatalf("remembered name = %q, want my-gateway", name)
	}

	// Exercise the real profile reset, but stop before starting a control client.
	errNoClient := errors.New("test: no control client")
	b.ForTest().SetControlClientGetter(func(controlclient.Options) (controlclient.Client, error) { return nil, errNoClient })
	if err := b.NewProfile(); !errors.Is(err, errNoClient) {
		t.Fatalf("NewProfile = %v, want %v", err, errNoClient)
	}
	wantReason(t, b, ExitNodeOK)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastKnownID != "" || e.lastKnownName != "" {
		t.Errorf("profile reset retained %q / %q", e.lastKnownID, e.lastKnownName)
	}
}

// Route updates must use the live peer map, not the original full netmap.
func TestExitNodeRouteChangesOnNetmapDelta(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	node, _ := b.NodeBackend().PeerByStableID("exit1")
	peer := node.AsStruct()
	for _, offerRoutes := range []bool{false, true} {
		peer.AllowedIPs = nil
		want := ExitNodeNoExitRoutes
		if offerRoutes {
			peer.AllowedIPs = tsaddr.ExitRoutes()
			want = ExitNodeOK
		}
		muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
			PeersChanged: []*tailcfg.Node{peer.Clone()},
		}, time.Unix(123, 0))
		if !ok || !b.UpdateNetmapDelta(muts) {
			t.Fatal("failed to apply peer route update")
		}
		wantReason(t, b, want)
	}
}

func TestPolicyOverrideEvents(t *testing.T) {
	if !buildfeatures.HasSystemPolicy {
		t.Skip("system policy omitted")
	}
	sys := tsd.NewSystem()
	sys.PolicyClient.Set(policytest.Config{
		pkey.ExitNodeID:            "missing",
		pkey.AllowExitNodeOverride: true,
	})
	b := newExitNodeHealthTestBackend(t, sys)
	wantReason(t, b, ExitNodeNotInTailnet)

	checkOverride := func(want bool) {
		t.Helper()
		e := extOf(t, b)
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.policyOverridden != want {
			t.Errorf("policyOverridden = %v, want %v", e.policyOverridden, want)
		}
		if got := e.forcedByPolicy(e.policyOverridden); got != !want {
			t.Errorf("forcedByPolicy = %v, want %v", got, !want)
		}
	}
	checkOverride(false)
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{
		ExitNodeIDSet: true,
		Prefs:         ipn.Prefs{ExitNodeID: "exit1"},
	}); err != nil {
		t.Fatal(err)
	}
	checkOverride(true)

	// Disconnecting resets the override, even without changing the selection.
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{WantRunningSet: true}); err != nil {
		t.Fatal(err)
	}
	checkOverride(false)
	wantReason(t, b, ExitNodeOK)
}

// An empty peer list is evidence of a missing exit node only after the node
// has received network configuration. Clearing that configuration must stop
// evaluation, and receiving it again must resume evaluation.
func TestNetworkConfigurationGatesDetection(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().ApplyNetMap(nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "missing"})
	wantReason(t, b, ExitNodeOK)

	nm := exitNodeHealthTestNetMap()
	nm.Peers = nil
	for range 2 {
		b.ForTest().ApplyNetMap(nm)
		wantReason(t, b, ExitNodeNotInTailnet)
		b.ForTest().ApplyNetMap(nil)
		wantReason(t, b, ExitNodeOK)
	}
}
