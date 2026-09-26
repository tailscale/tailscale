// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package integration

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/cmd/tailscale/tsdnsjsonv0"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// The tests in this file cover DNS and routing state that reaches the OS only
// through the Windows DNS manager and router. They also run 3x nightly.

// startSmokeNode brings up a node and returns it with its control-side key.
// It fails if the node isn't in TUN mode, which a userspace node would pass.
func startSmokeNode(t *testing.T, env *TestEnv) (*TestNode, key.NodePublic) {
	t.Helper()
	n := NewTestNode(t, env)
	d := n.StartDaemon()
	n.AwaitResponding()
	n.MustUp()
	n.AwaitRunning()
	t.Cleanup(func() { d.MustCleanShutdown(t) })

	st := n.MustStatus()
	if !st.TUN {
		t.Fatal("node is not in TUN mode; the service did not start")
	}
	return n, st.Self.PublicKey
}

// dnsStatus returns the parsed output of "tailscale dns status --json".
func dnsStatus(t *testing.T, n *TestNode) *tsdnsjsonv0.StatusResponse {
	t.Helper()
	out, err := n.TailscaleForOutput("dns", "status", "--json").Output()
	if err != nil {
		t.Fatalf("dns status: %v", err)
	}
	st := new(tsdnsjsonv0.StatusResponse)
	if err := json.Unmarshal(out, st); err != nil {
		t.Fatalf("parsing dns status: %v\n%s", err, out)
	}
	return st
}

// controlHostinfo returns the node's Hostinfo as control last received it.
func controlHostinfo(env *TestEnv, k key.NodePublic) (tailcfg.HostinfoView, error) {
	n := env.Control.Node(k)
	if n == nil {
		return tailcfg.HostinfoView{}, fmt.Errorf("node %v not found in control", k.ShortString())
	}
	if !n.Hostinfo.Valid() {
		return tailcfg.HostinfoView{}, fmt.Errorf("node %v has no Hostinfo", k.ShortString())
	}
	return n.Hostinfo, nil
}

func TestWindowsServiceMagicDNS(t *testing.T) {
	const magicDNSDomain = "smoke.example.com"

	tstest.Parallel(t)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = magicDNSDomain
		control.DNSConfig = &tailcfg.DNSConfig{Proxied: true}
	}))
	n, _ := startSmokeNode(t, env)

	if err := tstest.WaitFor(20*time.Second, func() error {
		st := dnsStatus(t, n)
		if !st.TailscaleDNS {
			return fmt.Errorf("TailscaleDNS = false; want true")
		}
		if st.CurrentTailnet == nil {
			return fmt.Errorf("no CurrentTailnet in dns status")
		}
		if got := st.CurrentTailnet.MagicDNSSuffix; got != magicDNSDomain {
			return fmt.Errorf("MagicDNSSuffix = %q; want %q", got, magicDNSDomain)
		}
		if st.CurrentTailnet.SelfDNSName == "" {
			return fmt.Errorf("SelfDNSName is empty")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsServiceSplitDNS(t *testing.T) {
	const (
		magicDNSDomain = "smoke.example.com"
		splitDomain    = "corp.example.com"
		splitResolver  = "1.1.1.1"
	)

	tstest.Parallel(t)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = magicDNSDomain
		control.DNSConfig = &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				splitDomain: {{Addr: splitResolver}},
			},
		}
	}))
	n, _ := startSmokeNode(t, env)

	if err := tstest.WaitFor(20*time.Second, func() error {
		st := dnsStatus(t, n)
		got := st.SplitDNSRoutes[splitDomain]
		if len(got) != 1 {
			return fmt.Errorf("SplitDNSRoutes[%q] = %v; want 1 resolver", splitDomain, got)
		}
		if got[0].Addr != splitResolver {
			return fmt.Errorf("SplitDNSRoutes[%q] resolver = %q; want %q", splitDomain, got[0].Addr, splitResolver)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsServiceShieldsUp(t *testing.T) {
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n, k := startSmokeNode(t, env)

	// Hostinfo is what the client reported to control, so this fails if the
	// pref never reached the daemon or was never pushed upstream.
	wantShieldsUp := func(want bool) {
		t.Helper()
		if err := tstest.WaitFor(20*time.Second, func() error {
			hi, err := controlHostinfo(env, k)
			if err != nil {
				return err
			}
			if got := hi.ShieldsUp(); got != want {
				return fmt.Errorf("Hostinfo.ShieldsUp = %v; want %v", got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	wantShieldsUp(false)

	if err := n.Tailscale("set", "--shields-up=true").Run(); err != nil {
		t.Fatalf("set --shields-up=true: %v", err)
	}
	wantShieldsUp(true)

	if err := n.Tailscale("set", "--shields-up=false").Run(); err != nil {
		t.Fatalf("set --shields-up=false: %v", err)
	}
	wantShieldsUp(false)
}

func TestWindowsServiceAdvertiseRoutes(t *testing.T) {
	route := netip.MustParsePrefix("10.1.2.3/32")

	tstest.Parallel(t)
	env := NewTestEnv(t)
	n, k := startSmokeNode(t, env)

	if err := n.Tailscale("set", "--advertise-routes="+route.String()).Run(); err != nil {
		t.Fatalf("set --advertise-routes: %v", err)
	}

	prefs, err := n.LocalClient().GetPrefs(t.Context())
	if err != nil {
		t.Fatalf("GetPrefs: %v", err)
	}
	if !slices.Contains(prefs.AdvertiseRoutes, route) {
		t.Fatalf("AdvertiseRoutes = %v; want to contain %v", prefs.AdvertiseRoutes, route)
	}

	// RoutableIPs is derived from the prefs by the client and sent to control,
	// so it only appears once the daemon has accepted and reported the route.
	if err := tstest.WaitFor(20*time.Second, func() error {
		hi, err := controlHostinfo(env, k)
		if err != nil {
			return err
		}
		if !views.SliceContains(hi.RoutableIPs(), route) {
			return fmt.Errorf("Hostinfo.RoutableIPs = %v; want to contain %v", hi.RoutableIPs().AsSlice(), route)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
