// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailnetsyspolicy

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

// newTestBackend returns a backend with the extension initialized and
// [pkey.AllowTailnetSysPolicy] set to allow in a device policy store.
func newTestBackend(t *testing.T, allow bool) *ipnlocal.LocalBackend {
	t.Helper()
	err := setting.SetDefinitionsForTest(t,
		setting.NewDefinition(pkey.AllowTailnetSysPolicy, setting.DeviceSetting, setting.BooleanValue),
		setting.NewDefinition(pkey.ControlURL, setting.DeviceSetting, setting.StringValue),
		setting.NewDefinition(pkey.AllowedSuggestedExitNodes, setting.ProfileSetting, setting.StringListValue),
		setting.NewDefinition(pkey.AllowExitNodeOverride, setting.ProfileSetting, setting.BooleanValue),
		setting.NewDefinition(pkey.EnableTailscaleDNS, setting.ProfileSetting, setting.PreferenceOptionValue),
		setting.NewDefinition(pkey.EnableTailscaleSubnets, setting.ProfileSetting, setting.PreferenceOptionValue),
		setting.NewDefinition(pkey.ExitNodeAllowLANAccess, setting.ProfileSetting, setting.PreferenceOptionValue),
		setting.NewDefinition(pkey.ExitNodeID, setting.ProfileSetting, setting.StringValue),
		setting.NewDefinition(pkey.ReconnectAfter, setting.ProfileSetting, setting.DurationValue),
		setting.NewDefinition(pkey.KeyExpirationNoticeTime, setting.UserSetting, setting.DurationValue),
	)
	if err != nil {
		t.Fatalf("SetDefinitionsForTest: %v", err)
	}
	allowStore = source.NewTestStoreOf(t, source.TestSettingOf(pkey.AllowTailnetSysPolicy, allow))
	if _, err := rsop.RegisterStoreForTest(t, "Allow", setting.DeviceScope, allowStore); err != nil {
		t.Fatalf("RegisterStoreForTest: %v", err)
	}
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.PolicyClient.Set(testPolicyClient{})
	b := ipnlocaltest.NewBackendWithSys(t, sys)
	b.ForTest().InitExtensions()
	if err := b.ForTest().SetPersist(&persist.Persist{}); err != nil {
		t.Fatalf("SetPersist: %v", err)
	}
	return b
}

// allowStore is the device policy store with [pkey.AllowTailnetSysPolicy]
// registered by newTestBackend.
var allowStore *source.TestStore

// numTailnetSettings returns the number of settings in the effective policy
// other than [pkey.AllowTailnetSysPolicy].
func numTailnetSettings(t *testing.T) int {
	t.Helper()
	return effectivePolicy(t).Len() - 1
}

func testNetMap(policy ...tailcfg.RawMessage) *netmap.NetworkMap {
	self := &tailcfg.Node{
		ID:                10,
		StableID:          "self",
		Key:               key.NewNode().Public(),
		Name:              "self.example.ts.net.",
		Hostinfo:          (&tailcfg.Hostinfo{}).View(),
		Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		MachineAuthorized: true,
	}
	if policy != nil {
		self.CapMap = tailcfg.NodeCapMap{nodecap.TailnetSysPolicy: policy}
	}
	return &netmap.NetworkMap{SelfNode: self.View()}
}

// testPolicyClient is a [policyclient.Client] that reads the effective policy
// from the registered stores, as tailscaled's client does outside of tests.
type testPolicyClient struct {
	policyclient.NoPolicyClient
}

func policyFor(uid string) (*rsop.Policy, error) {
	if uid != "" {
		return rsop.PolicyFor(setting.UserScopeOf(uid))
	}
	return rsop.PolicyFor(setting.DefaultScope())
}

func getSetting[T any](key pkey.Key, def T) (T, error) {
	policy, err := policyFor("")
	if err != nil {
		return def, err
	}
	if v, ok := policy.Get().Get(key).(T); ok {
		return v, nil
	}
	return def, nil
}

func (testPolicyClient) GetString(key pkey.Key, def string) (string, error) {
	return getSetting(key, def)
}

func (testPolicyClient) GetStringArray(key pkey.Key, def []string) ([]string, error) {
	return getSetting(key, def)
}

func (testPolicyClient) GetBoolean(key pkey.Key, def bool) (bool, error) {
	return getSetting(key, def)
}

func (testPolicyClient) GetDuration(key pkey.Key, def time.Duration) (time.Duration, error) {
	return getSetting(key, def)
}

func (testPolicyClient) GetPreferenceOption(key pkey.Key, def ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	return getSetting(key, def)
}

func (testPolicyClient) GetPolicySnapshot(uid string) (*policyclient.PolicySnapshot, error) {
	policy, err := policyFor(uid)
	if err != nil {
		return nil, err
	}
	return policy.Get(), nil
}

func (testPolicyClient) RegisterChangeCallback(uid string, cb func(policyclient.PolicyChange)) (func(), error) {
	policy, err := policyFor(uid)
	if err != nil {
		return nil, err
	}
	return policy.RegisterChangeCallback(cb), nil
}

// effectivePolicy returns the policy for the scope used by LocalBackend.
func effectivePolicy(t *testing.T) *setting.Snapshot {
	t.Helper()
	policy, err := policyFor("")
	if err != nil {
		t.Fatalf("PolicyFor: %v", err)
	}
	return policy.Get()
}

func waitForPrefs(t *testing.T, b *ipnlocal.LocalBackend, what string, cond func(ipn.PrefsView) bool) {
	t.Helper()
	err := tstest.WaitFor(10*time.Second, func() error {
		if !cond(b.Prefs()) {
			return errNotYet
		}
		return nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for prefs: %s; got %v", what, b.Prefs().Pretty())
	}
}

type notYetError struct{}

func (notYetError) Error() string { return "not yet" }

var errNotYet = notYetError{}

func TestSettings(t *testing.T) {
	b := newTestBackend(t, true)
	b.ForTest().ApplyNetMap(testNetMap(
		`{
			"AllowedSuggestedExitNodes": ["node1", "node2"],
			"ExitNode.AllowOverride": true,
			"ExitNodeAllowLANAccess": "always",
			"ExitNodeID": "node1",
			"KeyExpirationNotice": "48h",
			"ReconnectAfter": "5m",
			"UseTailscaleDNSSettings": "never",
			"UseTailscaleSubnets": "never",
			"LoginURL": "https://login.example.com"
		}`,
	))

	// The effective policy is updated by the time the netmap is applied.
	got := effectivePolicy(t)
	want := map[pkey.Key]any{
		pkey.AllowedSuggestedExitNodes: []string{"node1", "node2"},
		pkey.AllowExitNodeOverride:     true,
		pkey.ExitNodeAllowLANAccess:    ptype.AlwaysByPolicy,
		pkey.ExitNodeID:                "node1",
		pkey.ReconnectAfter:            5 * time.Minute,
		pkey.EnableTailscaleDNS:        ptype.NeverByPolicy,
		pkey.EnableTailscaleSubnets:    ptype.NeverByPolicy,
	}
	for k, want := range want {
		got, err := got.GetErr(k)
		if err != nil {
			t.Errorf("%s: %v", k, err)
			continue
		}
		if gotList, ok := got.([]string); ok {
			if wantList := want.([]string); len(gotList) != len(wantList) || gotList[0] != wantList[0] || gotList[1] != wantList[1] {
				t.Errorf("%s = %v; want %v", k, gotList, wantList)
			}
		} else if got != want {
			t.Errorf("%s = %v; want %v", k, got, want)
		}
	}
	// Device and user settings cannot be configured via the node attribute.
	for _, k := range []pkey.Key{pkey.ControlURL, pkey.KeyExpirationNoticeTime} {
		if v, err := got.GetErr(k); err == nil {
			t.Errorf("%s = %v; want it not configured", k, v)
		}
	}

	waitForPrefs(t, b, "policy applied", func(p ipn.PrefsView) bool {
		return p.ExitNodeID() == "node1" && p.ExitNodeAllowLANAccess() && !p.CorpDNS() && !p.RouteAll()
	})

	// A change to the node attribute replaces the settings.
	b.ForTest().ApplyNetMap(testNetMap(`{"UseTailscaleDNSSettings": "always"}`))
	got = effectivePolicy(t)
	if numTailnetSettings(t) != 1 || got.Get(pkey.EnableTailscaleDNS) != ptype.AlwaysByPolicy {
		t.Errorf("policy = %v; want only %s", got, pkey.EnableTailscaleDNS)
	}
	waitForPrefs(t, b, "CorpDNS", func(p ipn.PrefsView) bool { return p.CorpDNS() })
}

func TestMultipleValues(t *testing.T) {
	b := newTestBackend(t, true)
	b.ForTest().ApplyNetMap(testNetMap(
		`{"ExitNodeID": "node1", "UseTailscaleSubnets": "never"}`,
		`not JSON`,
		`{"ExitNodeID": "node2"}`,
	))
	got := effectivePolicy(t)
	if got, want := got.Get(pkey.ExitNodeID), "node2"; got != want {
		t.Errorf("%s = %v; want %v", pkey.ExitNodeID, got, want)
	}
	if got, want := got.Get(pkey.EnableTailscaleSubnets), ptype.NeverByPolicy; got != want {
		t.Errorf("%s = %v; want %v", pkey.EnableTailscaleSubnets, got, want)
	}
}

func TestDevicePolicyWins(t *testing.T) {
	b := newTestBackend(t, true)
	store := source.NewTestStoreOf(t, source.TestSettingOf(pkey.ExitNodeID, "device-node"))
	if _, err := rsop.RegisterStoreForTest(t, "Device", setting.DeviceScope, store); err != nil {
		t.Fatalf("RegisterStoreForTest: %v", err)
	}
	b.ForTest().ApplyNetMap(testNetMap(`{"ExitNodeID": "node1", "ReconnectAfter": "5m"}`))
	got := effectivePolicy(t)
	if got, want := got.Get(pkey.ExitNodeID), "device-node"; got != want {
		t.Errorf("%s = %v; want %v", pkey.ExitNodeID, got, want)
	}
	if got, want := got.Get(pkey.ReconnectAfter), 5*time.Minute; got != want {
		t.Errorf("%s = %v; want %v", pkey.ReconnectAfter, got, want)
	}
}

// TestProfileSwitch verifies that the settings stop applying as soon as
// another profile becomes the current one.
func TestProfileSwitch(t *testing.T) {
	b := newTestBackend(t, true)
	b.ForTest().ApplyNetMap(testNetMap(`{"ExitNodeID": "node1", "UseTailscaleDNSSettings": "never"}`))
	waitForPrefs(t, b, "policy applied", func(p ipn.PrefsView) bool {
		return p.ExitNodeID() == "node1" && !p.CorpDNS()
	})
	oldProfile := b.CurrentProfile().ID()

	if err := b.NewProfile(); err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if numTailnetSettings(t) != 0 {
		t.Errorf("policy after a profile switch = %v; want none", effectivePolicy(t))
	}
	if p := b.Prefs(); p.ExitNodeID() != "" || !p.CorpDNS() {
		t.Errorf("new profile's prefs = %v; want them unaffected by the old profile's policy", p.Pretty())
	}

	// The old profile keeps the prefs the policy set, as with any other policy
	// that no longer applies, and gets the settings back with its netmap.
	if err := b.SwitchProfile(oldProfile); err != nil {
		t.Fatalf("SwitchProfile: %v", err)
	}
	if numTailnetSettings(t) != 0 {
		t.Errorf("policy before the netmap is received = %v; want none", effectivePolicy(t))
	}
	b.ForTest().ApplyNetMap(testNetMap(`{"ExitNodeID": "node2"}`))
	waitForPrefs(t, b, "ExitNodeID", func(p ipn.PrefsView) bool { return p.ExitNodeID() == "node2" })
}

// TestAllowTailnetSysPolicy verifies that the node attribute is only used
// while [pkey.AllowTailnetSysPolicy] is enabled.
func TestAllowTailnetSysPolicy(t *testing.T) {
	b := newTestBackend(t, false)
	b.ForTest().ApplyNetMap(testNetMap(`{"ExitNodeID": "node1"}`))
	if numTailnetSettings(t) != 0 {
		t.Fatalf("policy = %v; want no tailnet settings", effectivePolicy(t))
	}

	waitForExitNodeID := func(want any) {
		t.Helper()
		err := tstest.WaitFor(10*time.Second, func() error {
			if effectivePolicy(t).Get(pkey.ExitNodeID) != want {
				return errNotYet
			}
			return nil
		})
		if err != nil {
			t.Fatalf("timed out waiting for %s = %v; policy = %v", pkey.ExitNodeID, want, effectivePolicy(t))
		}
	}
	allowStore.SetBooleans(source.TestSettingOf(pkey.AllowTailnetSysPolicy, true))
	waitForExitNodeID("node1")
	waitForPrefs(t, b, "ExitNodeID", func(p ipn.PrefsView) bool { return p.ExitNodeID() == "node1" })

	allowStore.SetBooleans(source.TestSettingOf(pkey.AllowTailnetSysPolicy, false))
	waitForExitNodeID(nil)
}

// TestNoStoreAfterShutdown verifies that the store is not registered
// by an update that arrives after the extension has been shut down.
func TestNoStoreAfterShutdown(t *testing.T) {
	b := newTestBackend(t, true)
	e, ok := b.FindExtensionByName(featureName).(*extension)
	if !ok {
		t.Fatalf("extension %q not found", featureName)
	}
	if err := e.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	b.ForTest().ApplyNetMap(testNetMap(`{"ExitNodeID": "node1"}`))
	if numTailnetSettings(t) != 0 {
		t.Errorf("policy after Shutdown = %v; want no tailnet settings", effectivePolicy(t))
	}
}
