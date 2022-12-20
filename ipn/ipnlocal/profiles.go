// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"time"

	"golang.org/x/exp/slices"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/strs"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
)

// profileManager is a wrapper around a StateStore that manages
// multiple profiles and the current profile.
type profileManager struct {
	store ipn.StateStore
	logf  logger.Logf

	currentUserID  ipn.WindowsUserID
	knownProfiles  map[ipn.ProfileID]*ipn.LoginProfile
	currentProfile *ipn.LoginProfile // always non-nil
	prefs          ipn.PrefsView     // always Valid.

	// isNewProfile is a sentinel value that indicates that the
	// current profile is new and has not been saved to disk yet.
	// It is reset to false after a call to SetPrefs with a filled
	// in LoginName.
	isNewProfile bool
}

// CurrentUserID returns the current user ID. It is only non-empty on
// Windows where we have a multi-user system.
func (pm *profileManager) CurrentUserID() ipn.WindowsUserID {
	return pm.currentUserID
}

// SetCurrentUserID sets the current user ID. The uid is only non-empty
// on Windows where we have a multi-user system.
func (pm *profileManager) SetCurrentUserID(uid ipn.WindowsUserID) error {
	if pm.currentUserID == uid {
		return nil
	}
	prev := pm.currentUserID
	pm.currentUserID = uid
	if uid == "" && prev != "" {
		// This is a local user logout, or app shutdown.
		// Clear the current profile.
		pm.NewProfile()
		return nil
	}

	// Read the CurrentProfileKey from the store which stores
	// the selected profile for the current user.
	b, err := pm.store.ReadState(ipn.CurrentProfileKey(string(uid)))
	if err == ipn.ErrStateNotExist || len(b) == 0 {
		pm.NewProfile()
		return nil
	}

	// Now attempt to load the profile using the key we just read.
	pk := ipn.StateKey(string(b))
	prof := pm.findProfileByKey(pk)
	if prof == nil {
		pm.NewProfile()
		return nil
	}
	prefs, err := pm.loadSavedPrefs(pk)
	if err != nil {
		pm.NewProfile()
		return err
	}
	pm.currentProfile = prof
	pm.prefs = prefs
	pm.isNewProfile = false
	return nil
}

// matchingProfiles returns all profiles that match the given predicate and
// belong to the currentUserID.
func (pm *profileManager) matchingProfiles(f func(*ipn.LoginProfile) bool) (out []*ipn.LoginProfile) {
	for _, p := range pm.knownProfiles {
		if p.LocalUserID == pm.currentUserID && f(p) {
			out = append(out, p)
		}
	}
	return out
}

// findProfilesByNodeID returns all profiles that have the provided nodeID and
// belong to the same control server.
func (pm *profileManager) findProfilesByNodeID(controlURL string, nodeID tailcfg.StableNodeID) []*ipn.LoginProfile {
	if nodeID.IsZero() {
		return nil
	}
	return pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.NodeID == nodeID && p.ControlURL == controlURL
	})
}

// findProfilesByUserID returns all profiles that have the provided userID and
// belong to the same control server.
func (pm *profileManager) findProfilesByUserID(controlURL string, userID tailcfg.UserID) []*ipn.LoginProfile {
	if userID.IsZero() {
		return nil
	}
	return pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.UserProfile.ID == userID && p.ControlURL == controlURL
	})
}

// ProfileIDForName returns the profile ID for the profile with the
// given name. It returns "" if no such profile exists.
func (pm *profileManager) ProfileIDForName(name string) ipn.ProfileID {
	p := pm.findProfileByName(name)
	if p == nil {
		return ""
	}
	return p.ID
}

func (pm *profileManager) findProfileByName(name string) *ipn.LoginProfile {
	out := pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.Name == name
	})
	if len(out) == 0 {
		return nil
	}
	if len(out) > 1 {
		pm.logf("[unxpected] multiple profiles with the same name")
	}
	return out[0]
}

func (pm *profileManager) findProfileByKey(key ipn.StateKey) *ipn.LoginProfile {
	out := pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.Key == key
	})
	if len(out) == 0 {
		return nil
	}
	if len(out) > 1 {
		pm.logf("[unxpected] multiple profiles with the same key")
	}
	return out[0]
}

func (pm *profileManager) setUnattendedModeAsConfigured() error {
	if pm.currentUserID == "" {
		return nil
	}

	if pm.prefs.ForceDaemon() {
		return pm.store.WriteState(ipn.ServerModeStartKey, []byte(pm.currentProfile.Key))
	} else {
		return pm.store.WriteState(ipn.ServerModeStartKey, nil)
	}
}

// Reset unloads the current profile, if any.
func (pm *profileManager) Reset() {
	pm.currentUserID = ""
	pm.NewProfile()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// SetPrefs sets the current profile's prefs to the provided value.
// It also saves the prefs to the StateStore. It stores a copy of the
// provided prefs, which may be accessed via CurrentPrefs.
func (pm *profileManager) SetPrefs(prefsIn ipn.PrefsView) error {
	prefs := prefsIn.AsStruct().View()
	newPersist := prefs.Persist().AsStruct()
	if newPersist == nil || newPersist.LoginName == "" {
		return pm.setPrefsLocked(prefs)
	}
	up := newPersist.UserProfile
	if up.LoginName == "" {
		// Backwards compatibility with old prefs files.
		up.LoginName = newPersist.LoginName
	} else {
		newPersist.LoginName = up.LoginName
	}
	if up.DisplayName == "" {
		up.DisplayName = up.LoginName
	}
	cp := pm.currentProfile
	if pm.isNewProfile {
		pm.isNewProfile = false
		// Check if we already have a profile for this user.
		existing := pm.findProfilesByUserID(prefs.ControlURL(), newPersist.UserProfile.ID)
		// Also check if we have a profile with the same NodeID.
		existing = append(existing, pm.findProfilesByNodeID(prefs.ControlURL(), newPersist.NodeID)...)
		if len(existing) == 0 {
			cp.ID, cp.Key = newUnusedID(pm.knownProfiles)
		} else {
			// Only one profile per user/nodeID should exist.
			for _, p := range existing[1:] {
				// Best effort cleanup.
				pm.DeleteProfile(p.ID)
			}
			cp = existing[0]
		}
		cp.LocalUserID = pm.currentUserID
	}
	if prefs.ProfileName() != "" {
		cp.Name = prefs.ProfileName()
	} else {
		cp.Name = up.LoginName
	}
	cp.ControlURL = prefs.ControlURL()
	cp.UserProfile = newPersist.UserProfile
	cp.NodeID = newPersist.NodeID
	pm.knownProfiles[cp.ID] = cp
	pm.currentProfile = cp
	if err := pm.writeKnownProfiles(); err != nil {
		return err
	}
	if err := pm.setAsUserSelectedProfileLocked(); err != nil {
		return err
	}
	if err := pm.setPrefsLocked(prefs); err != nil {
		return err
	}
	return nil
}

func newUnusedID(knownProfiles map[ipn.ProfileID]*ipn.LoginProfile) (ipn.ProfileID, ipn.StateKey) {
	var idb [2]byte
	for {
		rand.Read(idb[:])
		id := ipn.ProfileID(fmt.Sprintf("%x", idb))
		if _, ok := knownProfiles[id]; ok {
			continue
		}
		return id, ipn.StateKey("profile-" + id)
	}
}

// setPrefsLocked sets the current profile's prefs to the provided value.
// It also saves the prefs to the StateStore, if the current profile
// is not new.
func (pm *profileManager) setPrefsLocked(clonedPrefs ipn.PrefsView) error {
	pm.prefs = clonedPrefs
	if pm.isNewProfile {
		return nil
	}
	if err := pm.writePrefsToStore(pm.currentProfile.Key, pm.prefs); err != nil {
		return err
	}
	return pm.setUnattendedModeAsConfigured()
}

func (pm *profileManager) writePrefsToStore(key ipn.StateKey, prefs ipn.PrefsView) error {
	if key == "" {
		return nil
	}
	if err := pm.store.WriteState(key, prefs.ToBytes()); err != nil {
		pm.logf("WriteState(%q): %v", key, err)
		return err
	}
	return nil
}

// Profiles returns the list of known profiles.
func (pm *profileManager) Profiles() []ipn.LoginProfile {
	profiles := pm.matchingProfiles(func(*ipn.LoginProfile) bool { return true })
	slices.SortFunc(profiles, func(a, b *ipn.LoginProfile) bool {
		return a.Name < b.Name
	})
	out := make([]ipn.LoginProfile, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, *p)
	}
	return out
}

// SwitchProfile switches to the profile with the given id.
// If the profile is not known, it returns an errProfileNotFound.
func (pm *profileManager) SwitchProfile(id ipn.ProfileID) error {
	metricSwitchProfile.Add(1)

	kp, ok := pm.knownProfiles[id]
	if !ok {
		return errProfileNotFound
	}

	if pm.currentProfile != nil && kp.ID == pm.currentProfile.ID && pm.prefs.Valid() {
		return nil
	}
	if kp.LocalUserID != pm.currentUserID {
		return fmt.Errorf("profile %q is not owned by current user", id)
	}
	prefs, err := pm.loadSavedPrefs(kp.Key)
	if err != nil {
		return err
	}
	pm.prefs = prefs
	pm.currentProfile = kp
	pm.isNewProfile = false
	return pm.setAsUserSelectedProfileLocked()
}

func (pm *profileManager) setAsUserSelectedProfileLocked() error {
	k := ipn.CurrentProfileKey(string(pm.currentUserID))
	return pm.store.WriteState(k, []byte(pm.currentProfile.Key))
}

func (pm *profileManager) loadSavedPrefs(key ipn.StateKey) (ipn.PrefsView, error) {
	bs, err := pm.store.ReadState(key)
	if err == ipn.ErrStateNotExist || len(bs) == 0 {
		return defaultPrefs, nil
	}
	if err != nil {
		return ipn.PrefsView{}, err
	}
	savedPrefs, err := ipn.PrefsFromBytes(bs)
	if err != nil {
		return ipn.PrefsView{}, fmt.Errorf("PrefsFromBytes: %v", err)
	}
	pm.logf("using backend prefs for %q: %v", key, savedPrefs.Pretty())

	// Ignore any old stored preferences for https://login.tailscale.com
	// as the control server that would override the new default of
	// controlplane.tailscale.com.
	if savedPrefs.ControlURL != "" &&
		savedPrefs.ControlURL != ipn.DefaultControlURL &&
		ipn.IsLoginServerSynonym(savedPrefs.ControlURL) {
		savedPrefs.ControlURL = ""
	}
	return savedPrefs.View(), nil
}

// CurrentProfile returns the current LoginProfile.
// The value may be zero if the profile is not persisted.
func (pm *profileManager) CurrentProfile() ipn.LoginProfile {
	return *pm.currentProfile
}

// errProfileNotFound is returned by methods that accept a ProfileID.
var errProfileNotFound = errors.New("profile not found")

// DeleteProfile removes the profile with the given id. It returns
// errProfileNotFound if the profile does not exist.
// If the profile is the current profile, it is the equivalent of
// calling NewProfile() followed by DeleteProfile(id). This is
// useful for deleting the last profile. In other cases, it is
// recommended to call SwitchProfile() first.
func (pm *profileManager) DeleteProfile(id ipn.ProfileID) error {
	metricDeleteProfile.Add(1)

	if id == "" && pm.isNewProfile {
		// Deleting the in-memory only new profile, just create a new one.
		pm.NewProfile()
		return nil
	}
	kp, ok := pm.knownProfiles[id]
	if !ok {
		return errProfileNotFound
	}
	if kp.ID == pm.currentProfile.ID {
		pm.NewProfile()
	}
	if err := pm.store.WriteState(kp.Key, nil); err != nil {
		return err
	}
	delete(pm.knownProfiles, id)
	return pm.writeKnownProfiles()
}

func (pm *profileManager) writeKnownProfiles() error {
	b, err := json.Marshal(pm.knownProfiles)
	if err != nil {
		return err
	}
	return pm.store.WriteState(ipn.KnownProfilesStateKey, b)
}

// NewProfile creates and switches to a new unnamed profile. The new profile is
// not persisted until SetPrefs is called with a logged-in user.
func (pm *profileManager) NewProfile() {
	metricNewProfile.Add(1)

	pm.prefs = defaultPrefs
	pm.isNewProfile = true
	pm.currentProfile = &ipn.LoginProfile{}
}

// defaultPrefs is the default prefs for a new profile.
var defaultPrefs = func() ipn.PrefsView {
	prefs := ipn.NewPrefs()
	prefs.WantRunning = false

	prefs.ControlURL = winutil.GetPolicyString("LoginURL", "")

	if exitNode := winutil.GetPolicyString("ExitNodeIP", ""); exitNode != "" {
		if ip, err := netip.ParseAddr(exitNode); err == nil {
			prefs.ExitNodeIP = ip
		}
	}

	// Allow Incoming (used by the UI) is the negation of ShieldsUp (used by the
	// backend), so this has to convert between the two conventions.
	prefs.ShieldsUp = winutil.GetPolicyString("AllowIncomingConnections", "") == "never"
	prefs.ForceDaemon = winutil.GetPolicyString("UnattendedMode", "") == "always"

	return prefs.View()
}()

// Store returns the StateStore used by the ProfileManager.
func (pm *profileManager) Store() ipn.StateStore {
	return pm.store
}

// CurrentPrefs returns a read-only view of the current prefs.
// The returned view is always valid.
func (pm *profileManager) CurrentPrefs() ipn.PrefsView {
	return pm.prefs
}

// ReadStartupPrefsForTest reads the startup prefs from disk. It is only used for testing.
func ReadStartupPrefsForTest(logf logger.Logf, store ipn.StateStore) (ipn.PrefsView, error) {
	pm, err := newProfileManager(store, logf, "")
	if err != nil {
		return ipn.PrefsView{}, err
	}
	return pm.CurrentPrefs(), nil
}

// newProfileManager creates a new ProfileManager using the provided StateStore.
// It also loads the list of known profiles from the StateStore.
// If a state key is provided, it will be used to load the current profile.
func newProfileManager(store ipn.StateStore, logf logger.Logf, stateKey ipn.StateKey) (*profileManager, error) {
	return newProfileManagerWithGOOS(store, logf, stateKey, envknob.GOOS())
}

func readAutoStartKey(store ipn.StateStore, goos string) (ipn.StateKey, error) {
	startKey := ipn.CurrentProfileStateKey
	if goos == "windows" {
		// When tailscaled runs on Windows it is not typically run unattended.
		// So we can't use the profile mechanism to load the profile at startup.
		startKey = ipn.ServerModeStartKey
	}
	autoStartKey, err := store.ReadState(startKey)
	if err != nil && err != ipn.ErrStateNotExist {
		return "", fmt.Errorf("calling ReadState on state store: %w", err)
	}
	return ipn.StateKey(autoStartKey), nil
}

func readKnownProfiles(store ipn.StateStore) (map[ipn.ProfileID]*ipn.LoginProfile, error) {
	var knownProfiles map[ipn.ProfileID]*ipn.LoginProfile
	prfB, err := store.ReadState(ipn.KnownProfilesStateKey)
	switch err {
	case nil:
		if err := json.Unmarshal(prfB, &knownProfiles); err != nil {
			return nil, fmt.Errorf("unmarshaling known profiles: %w", err)
		}
	case ipn.ErrStateNotExist:
		knownProfiles = make(map[ipn.ProfileID]*ipn.LoginProfile)
	default:
		return nil, fmt.Errorf("calling ReadState on state store: %w", err)
	}
	return knownProfiles, nil
}

func newProfileManagerWithGOOS(store ipn.StateStore, logf logger.Logf, stateKey ipn.StateKey, goos string) (*profileManager, error) {
	logf = logger.WithPrefix(logf, "pm: ")
	if stateKey == "" {
		var err error
		stateKey, err = readAutoStartKey(store, goos)
		if err != nil {
			return nil, err
		}
	}

	knownProfiles, err := readKnownProfiles(store)
	if err != nil {
		return nil, err
	}

	pm := &profileManager{
		store:         store,
		knownProfiles: knownProfiles,
		logf:          logf,
	}

	if stateKey != "" {
		for _, v := range knownProfiles {
			if v.Key == stateKey {
				pm.currentProfile = v
			}
		}
		if pm.currentProfile == nil {
			if suf, ok := strs.CutPrefix(string(stateKey), "user-"); ok {
				pm.currentUserID = ipn.WindowsUserID(suf)
			}
			pm.NewProfile()
		} else {
			pm.currentUserID = pm.currentProfile.LocalUserID
		}
		prefs, err := pm.loadSavedPrefs(stateKey)
		if err != nil {
			return nil, err
		}
		if err := pm.setPrefsLocked(prefs); err != nil {
			return nil, err
		}
	} else if len(knownProfiles) == 0 && goos != "windows" {
		// No known profiles, try a migration.
		if err := pm.migrateFromLegacyPrefs(); err != nil {
			return nil, err
		}
	} else {
		pm.NewProfile()
	}

	return pm, nil
}

func (pm *profileManager) migrateFromLegacyPrefs() error {
	metricMigration.Add(1)
	pm.NewProfile()
	k := ipn.LegacyGlobalDaemonStateKey
	switch {
	case runtime.GOOS == "ios":
		k = "ipn-go-bridge"
	case version.IsSandboxedMacOS():
		k = "ipn-go-bridge"
	case runtime.GOOS == "android":
		k = "ipn-android"
	}
	prefs, err := pm.loadSavedPrefs(k)
	if err != nil {
		metricMigrationError.Add(1)
		return fmt.Errorf("calling ReadState on state store: %w", err)
	}
	pm.logf("migrating %q profile to new format", k)
	if err := pm.SetPrefs(prefs); err != nil {
		metricMigrationError.Add(1)
		return fmt.Errorf("migrating _daemon profile: %w", err)
	}
	// Do not delete the old state key, as we may be downgraded to an
	// older version that still relies on it.
	metricMigrationSuccess.Add(1)
	return nil
}

var (
	metricNewProfile    = clientmetric.NewCounter("profiles_new")
	metricSwitchProfile = clientmetric.NewCounter("profiles_switch")
	metricDeleteProfile = clientmetric.NewCounter("profiles_delete")

	metricMigration        = clientmetric.NewCounter("profiles_migration")
	metricMigrationError   = clientmetric.NewCounter("profiles_migration_error")
	metricMigrationSuccess = clientmetric.NewCounter("profiles_migration_success")
)
