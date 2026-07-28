// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package serviceclientprefs stores the desktop clients' saved service launch preferences, in a
// file per login profile.
package serviceclientprefs

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

const featureName = "serviceclientprefs"

// storeKey is the key under which a profile's service client prefs are stored.
const storeKey = "service-client-prefs"

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

// extension stores the service client prefs for the current login profile.
type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend
	host ipnext.Host // from Init

	// mu guards store and curPID, and the read/change/write in setServiceClientPref.
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
// profile-data/<id>/, which [ipnlocal.LocalBackend] removes when the profile is deleted.
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
		// No writable storage (ephemeral node, or a non-file [ipn.StateStore] like Kubernetes).
		// Service client prefs are only used by the desktop clients, so an in-memory store that
		// doesn't survive restarts is fine here.
		e.store = new(mem.Store)
		return
	}
	// Store the file under a dir plus a hex-encoded filename with no extension, matching
	// netmapcache.Store's layout so a shared store could read these files if we consolidate later.
	hexStoreKey := hex.EncodeToString([]byte(storeKey))
	path := filepath.Join(varRoot, ipnlocal.ProfileDataDir, string(pid), storeKey, hexStoreKey)
	st, err := store.NewFileStore(e.logf, path)
	if err != nil {
		e.logf("building store for profile %q: %v", pid, err)
		return
	}
	e.store = st
}
