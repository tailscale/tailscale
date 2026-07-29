// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package favorites stores the user's locally-pinned favorites (devices, exit nodes, and services)
// in a file per login profile. Pins are per-device and not synced across a user's devices.
package favorites

import (
	"encoding/hex"
	"path/filepath"
	"sync"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

// featureName is the extension name and also the storage namespace.
const featureName = "favorites"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
}

// newExtension is the [ipnext.NewExtensionFn] for this feature.
func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, featureName+": "),
		sb:   sb,
	}, nil
}

// extension stores the pinned favorites for the current login profile.
type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend
	host ipnext.Host // from Init

	// mu guards store and curPID, and the read/change/write in setPins.
	mu     sync.Mutex
	store  ipn.StateStore // for the current profile
	curPID ipn.ProfileID  // the profile store is built for
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension]. It subscribes to profile changes and sets up storage for the
// current profile.
func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)
	return nil
}

// Shutdown implements [ipnext.Extension].
func (e *extension) Shutdown() error { return nil }

// onChangeProfile builds the store for the profile we switched to. The prefs live under
// profile-data/<id>/, which [ipnlocal.LocalBackend] removes with the profile.
func (e *extension) onChangeProfile(profile ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	pid := profile.ID()
	if sameNode && e.curPID == pid && e.store != nil {
		// Same profile, just a prefs or metadata update; keep the store we already built.
		return
	}
	e.curPID = pid
	e.store = nil
	if pid == "" {
		return
	}
	varRoot := e.sb.TailscaleVarRoot()
	if varRoot == "" {
		// No writable storage (ephemeral node, or a non-file [ipn.StateStore] like Kubernetes);
		// fall back to memory, since pins not surviving a restart there is acceptable.
		e.store = new(mem.Store)
		return
	}
	// Hex-encoded filename with no extension, matching netmapcache.Store's layout so a shared
	// store could read these files if we consolidate later.
	hexStoreKey := hex.EncodeToString([]byte(featureName))
	path := filepath.Join(varRoot, ipnlocal.ProfileDataDir, string(pid), featureName, hexStoreKey)
	st, err := store.NewFileStore(e.logf, path)
	if err != nil {
		e.logf("building store for profile %q: %v", pid, err)
		return
	}
	e.store = st
}
