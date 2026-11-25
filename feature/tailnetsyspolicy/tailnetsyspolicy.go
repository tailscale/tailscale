// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailnetsyspolicy registers a policy store with the policy settings
// that the control plane sent to the current profile's node
// in the [nodecap.TailnetSysPolicy] node attribute.
package tailnetsyspolicy

import (
	"encoding/json"
	"sync"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

const featureName = "tailnet-syspolicy"

func init() {
	if feature.Register(featureName) {
		ipnext.RegisterExtension(featureName, newExtension)
	}
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, featureName+": "),
		polc: sb.Sys().PolicyClientOrDefault(),
	}, nil
}

// extension keeps a [setting.CurrentProfileScope] policy store in sync with
// the self node's [nodecap.TailnetSysPolicy] values. The store is only registered
// if [pkey.AllowTailnetSysPolicy] is enabled and the node has the attribute.
// Settings in the store are overridden by those configured for the device,
// such as via MDM.
type extension struct {
	logf logger.Logf
	polc policyclient.Client
	host ipnext.Host

	unregisterPolicyCb func()

	mu       sync.Mutex                      // lock order: LocalBackend.mu, then e.mu
	shutdown bool                            // whether Shutdown has been called
	reg      *rsop.StoreRegistration         // or nil if the store is not registered
	vals     views.Slice[tailcfg.RawMessage] // values the registered store was created from
}

func (e *extension) Name() string { return featureName }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	unregister, err := e.polc.RegisterChangeCallback("", func(pc policyclient.PolicyChange) {
		if pc.HasChanged(pkey.AllowTailnetSysPolicy) {
			e.update()
		}
	})
	if err != nil {
		return err
	}
	e.unregisterPolicyCb = unregister
	h.Hooks().OnSelfChange.Add(func(tailcfg.NodeView) { e.update() })
	// OnSelfChange is not called when a profile switch discards the self node.
	h.Hooks().ProfileStateChange.Add(func(ipn.LoginProfileView, ipn.PrefsView, bool) { e.update() })
	e.update()
	return nil
}

func (e *extension) Shutdown() error {
	e.unregisterPolicyCb()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown = true
	reg := e.reg
	e.reg, e.vals = nil, views.Slice[tailcfg.RawMessage]{}
	if reg == nil {
		return nil
	}
	return reg.Unregister()
}

// update registers, replaces or unregisters the store if the current node's
// [nodecap.TailnetSysPolicy] values or [pkey.AllowTailnetSysPolicy] have changed.
//
// When called by LocalBackend, LocalBackend.mu is held, and the store is
// updated before update returns, so on a profile switch the old profile's
// policy settings are gone before LocalBackend applies the policy to the
// new profile's prefs.
func (e *extension) update() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		// A policy change callback or a hook may still be running
		// after Shutdown and must not register the store again.
		return
	}

	var vals views.Slice[tailcfg.RawMessage]
	if allowed, _ := e.polc.GetBoolean(pkey.AllowTailnetSysPolicy, false); allowed {
		if self := e.host.NodeBackend().Self(); self.Valid() {
			vals = self.CapMap().Get(nodecap.TailnetSysPolicy)
		}
	}
	if views.SliceEqual(vals, e.vals) {
		return
	}

	var reg *rsop.StoreRegistration
	var err error
	switch {
	case vals.Len() == 0:
		err = e.reg.Unregister()
	case e.reg == nil:
		reg, err = rsop.RegisterStore("Tailnet", setting.CurrentProfileScope, source.NewJSONPolicyStore(e.parse(vals)))
	default:
		reg, err = e.reg.ReplaceStore(source.NewJSONPolicyStore(e.parse(vals)))
	}
	if err != nil {
		e.logf("failed to update the policy store: %v", err)
		return
	}
	e.reg, e.vals = reg, vals
}

// parse returns profile policy settings merged from vals, each of which is
// a JSON object that maps policy setting keys to values. If more than one of
// them has a value for the same key, the last one wins.
func (e *extension) parse(vals views.Slice[tailcfg.RawMessage]) map[string]any {
	var settings map[string]any
	for _, v := range vals.All() {
		if err := json.Unmarshal([]byte(v), &settings); err != nil {
			e.logf("ignoring an invalid %q value: %v", nodecap.TailnetSysPolicy, err)
		}
	}
	for k := range settings {
		if d, err := setting.DefinitionOf(pkey.Key(k)); err != nil || d.Scope() != setting.ProfileSetting {
			e.logf("ignoring %q: not a profile policy setting", k)
			delete(settings, k)
		}
	}
	return settings
}
