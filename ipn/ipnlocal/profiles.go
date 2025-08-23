// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
)

var debug = envknob.RegisterBool("TS_DEBUG_PROFILES")

// [profileManager] implements [ipnext.ProfileStore].
var _ ipnext.ProfileStore = (*profileManager)(nil)

// profileManager is a wrapper around an [ipn.StateStore] that manages
// multiple profiles and the current profile.
//
// It is not safe for concurrent use.
type profileManager struct {
	goos   string // used for TestProfileManagementWindows
	store  ipn.StateStore
	logf   logger.Logf
	health *health.Tracker

	currentUserID  ipn.WindowsUserID
	knownProfiles  map[ipn.ProfileID]ipn.LoginProfileView // always non-nil
	currentProfile ipn.LoginProfileView                   // always Valid (once [newProfileManager] returns).
	prefs          ipn.PrefsView                          // always Valid (once [newProfileManager] returns).

	// StateChangeHook is an optional hook that is called when the current profile or prefs change,
	// such as due to a profile switch or a change in the profile's preferences.
	// It is typically set by the [LocalBackend] to invert the dependency between
	// the [profileManager] and the [LocalBackend], so that instead of [LocalBackend]
	// asking [profileManager] for the state, we can have [profileManager] call
	// [LocalBackend] when the state changes. See also:
	// https://github.com/tailscale/tailscale/pull/15791#discussion_r2060838160
	StateChangeHook ipnext.ProfileStateChangeCallback

	// extHost is the bridge between [profileManager] and the registered [ipnext.Extension]s.
	// It may be nil in tests. A nil pointer is a valid, no-op host.
	extHost *ExtensionHost
}

// SetExtensionHost sets the [ExtensionHost] for the [profileManager].
// The specified host will be notified about profile and prefs changes
// and will immediately be notified about the current profile and prefs.
// A nil host is a valid, no-op host.
func (pm *profileManager) SetExtensionHost(host *ExtensionHost) {
	pm.extHost = host
	host.NotifyProfileChange(pm.currentProfile, pm.prefs, false)
}

func (pm *profileManager) dlogf(format string, args ...any) {
	if !debug() {
		return
	}
	pm.logf(format, args...)
}

func (pm *profileManager) WriteState(id ipn.StateKey, val []byte) error {
	return ipn.WriteState(pm.store, id, val)
}

// CurrentUserID returns the current user ID. It is only non-empty on
// Windows where we have a multi-user system.
func (pm *profileManager) CurrentUserID() ipn.WindowsUserID {
	return pm.currentUserID
}

// SetCurrentUserID sets the current user ID and switches to that user's default (last used) profile.
// If the specified user does not have a default profile, or the default profile could not be loaded,
// it creates a new one and switches to it. The uid is only non-empty on Windows where we have a multi-user system.
func (pm *profileManager) SetCurrentUserID(uid ipn.WindowsUserID) {
	if pm.currentUserID == uid {
		return
	}
	if _, _, err := pm.SwitchToDefaultProfileForUser(uid); err != nil {
		// SetCurrentUserID should never fail and must always switch to the
		// user's default profile or create a new profile for the current user.
		// Until we implement multi-user support and the new permission model,
		// and remove the concept of the "current user" completely, we must ensure
		// that when SetCurrentUserID exits, the profile in pm.currentProfile
		// is either an existing profile owned by the user, or a new, empty profile.
		pm.logf("%q's default profile cannot be used; creating a new one: %v", uid, err)
		pm.SwitchToNewProfileForUser(uid)
	}
}

// SwitchToProfile switches to the specified profile and (temporarily,
// while the "current user" is still a thing on Windows; see tailscale/corp#18342)
// sets its owner as the current user. The profile must be a valid profile
// returned by the [profileManager], such as by [profileManager.Profiles],
// [profileManager.ProfileByID], or [profileManager.NewProfileForUser].
//
// It is a shorthand for [profileManager.SetCurrentUserID] followed by
// [profileManager.SwitchProfileByID], but it is more efficient as it switches
// directly to the specified profile rather than switching to the user's
// default profile first. It is a no-op if the specified profile is already
// the current profile.
//
// As a special case, if the specified profile view is not valid, it resets
// both the current user and the profile to a new, empty profile not owned
// by any user.
//
// It returns the current profile and whether the call resulted in a profile change,
// or an error if the specified profile does not exist or its prefs could not be loaded.
//
// It may be called during [profileManager] initialization before [newProfileManager] returns
// and must check whether pm.currentProfile is Valid before using it.
func (pm *profileManager) SwitchToProfile(profile ipn.LoginProfileView) (cp ipn.LoginProfileView, changed bool, err error) {
	prefs := defaultPrefs
	switch {
	case !profile.Valid():
		// Create a new profile that is not associated with any user.
		profile = pm.NewProfileForUser("")
	case profile == pm.currentProfile,
		profile.ID() != "" && pm.currentProfile.Valid() && profile.ID() == pm.currentProfile.ID(),
		profile.ID() == "" && profile.Equals(pm.currentProfile) && prefs.Equals(pm.prefs):
		// The profile is already the current profile; no need to switch.
		//
		// It includes three cases:
		// 1. The target profile and the current profile are aliases referencing the [ipn.LoginProfile].
		//    The profile may be either a new (non-persisted) profile or an existing well-known profile.
		// 2. The target profile is a well-known, persisted profile with the same ID as the current profile.
		// 3. The target and the current profiles are both new (non-persisted) profiles and they are equal.
		//    At minimum, equality means that the profiles are owned by the same user on platforms that support it
		//    and the prefs are the same as well.
		return pm.currentProfile, false, nil
	case profile.ID() == "":
		// Copy the specified profile to prevent accidental mutation.
		profile = profile.AsStruct().View()
	default:
		// Find an existing profile by ID and load its prefs.
		kp, ok := pm.knownProfiles[profile.ID()]
		if !ok {
			// The profile ID is not valid; it may have been deleted or never existed.
			// As the target profile should have been returned by the [profileManager],
			// this is unexpected and might indicate a bug in the code.
			return pm.currentProfile, false, fmt.Errorf("[unexpected] %w: %s (%s)", errProfileNotFound, profile.Name(), profile.ID())
		}
		profile = kp
		if prefs, err = pm.loadSavedPrefs(profile.Key()); err != nil {
			return pm.currentProfile, false, fmt.Errorf("failed to load profile prefs for %s (%s): %w", profile.Name(), profile.ID(), err)
		}
	}

	if profile.ID() == "" { // new profile that has never been persisted
		metricNewProfile.Add(1)
	} else {
		metricSwitchProfile.Add(1)
	}

	pm.prefs = prefs
	pm.updateHealth()
	pm.currentProfile = profile
	pm.currentUserID = profile.LocalUserID()
	if err := pm.setProfileAsUserDefault(profile); err != nil {
		// This is not a fatal error; we've already switched to the profile.
		// But if updating the default profile fails, we should log it.
		pm.logf("failed to set %s (%s) as the default profile: %v", profile.Name(), profile.ID(), err)
	}

	if f := pm.StateChangeHook; f != nil {
		f(pm.currentProfile, pm.prefs, false)
	}
	// Do not call pm.extHost.NotifyProfileChange here; it is invoked in
	// [LocalBackend.resetForProfileChangeLocked] after the netmap reset.
	// TODO(nickkhyl): Consider moving it here (or into the stateChangeCb handler
	// in [LocalBackend]) once the profile/node state, including the netmap,
	// is actually tied to the current profile.

	return profile, true, nil
}

// DefaultUserProfile returns a read-only view of the default (last used) profile for the specified user.
// It returns a read-only view of a new, non-persisted profile if the specified user does not have a default profile.
func (pm *profileManager) DefaultUserProfile(uid ipn.WindowsUserID) ipn.LoginProfileView {
	// Read the CurrentProfileKey from the store which stores
	// the selected profile for the specified user.
	b, err := pm.store.ReadState(ipn.CurrentProfileKey(string(uid)))
	pm.dlogf("DefaultUserProfile: ReadState(%q) = %v, %v", string(uid), len(b), err)
	if err == ipn.ErrStateNotExist || len(b) == 0 {
		if runtime.GOOS == "windows" {
			pm.dlogf("DefaultUserProfile: windows: migrating from legacy preferences")
			profile, err := pm.migrateFromLegacyPrefs(uid)
			if err == nil {
				return profile
			}
			pm.logf("failed to migrate from legacy preferences: %v", err)
		}
		return pm.NewProfileForUser(uid)
	}

	pk := ipn.StateKey(string(b))
	prof := pm.findProfileByKey(uid, pk)
	if !prof.Valid() {
		pm.dlogf("DefaultUserProfile: no profile found for key: %q", pk)
		return pm.NewProfileForUser(uid)
	}
	return prof
}

// checkProfileAccess returns an [errProfileAccessDenied] if the current user
// does not have access to the specified profile.
func (pm *profileManager) checkProfileAccess(profile ipn.LoginProfileView) error {
	return pm.checkProfileAccessAs(pm.currentUserID, profile)
}

// checkProfileAccessAs returns an [errProfileAccessDenied] if the specified user
// does not have access to the specified profile.
func (pm *profileManager) checkProfileAccessAs(uid ipn.WindowsUserID, profile ipn.LoginProfileView) error {
	if uid != "" && profile.LocalUserID() != uid {
		return errProfileAccessDenied
	}
	return nil
}

// allProfilesFor returns all profiles accessible to the specified user.
// The returned profiles are sorted by Name.
func (pm *profileManager) allProfilesFor(uid ipn.WindowsUserID) []ipn.LoginProfileView {
	out := make([]ipn.LoginProfileView, 0, len(pm.knownProfiles))
	for _, p := range pm.knownProfiles {
		if pm.checkProfileAccessAs(uid, p) == nil {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b ipn.LoginProfileView) int {
		return cmp.Compare(a.Name(), b.Name())
	})
	return out
}

// matchingProfiles is like [profileManager.allProfilesFor], but returns only profiles
// matching the given predicate.
func (pm *profileManager) matchingProfiles(uid ipn.WindowsUserID, f func(ipn.LoginProfileView) bool) (out []ipn.LoginProfileView) {
	all := pm.allProfilesFor(uid)
	out = all[:0]
	for _, p := range all {
		if f(p) {
			out = append(out, p)
		}
	}
	return out
}

// findMatchingProfiles returns all profiles accessible to the current user
// that represent the same node/user as prefs.
// The returned profiles are sorted by Name.
func (pm *profileManager) findMatchingProfiles(uid ipn.WindowsUserID, prefs ipn.PrefsView) []ipn.LoginProfileView {
	return pm.matchingProfiles(uid, func(p ipn.LoginProfileView) bool {
		return p.ControlURL() == prefs.ControlURL() &&
			(p.UserProfile().ID == prefs.Persist().UserProfile().ID ||
				p.NodeID() == prefs.Persist().NodeID())
	})
}

// ProfileIDForName returns the profile ID for the profile with the
// given name. It returns "" if no such profile exists among profiles
// accessible to the current user.
func (pm *profileManager) ProfileIDForName(name string) ipn.ProfileID {
	p := pm.findProfileByName(pm.currentUserID, name)
	if !p.Valid() {
		return ""
	}
	return p.ID()
}

func (pm *profileManager) findProfileByName(uid ipn.WindowsUserID, name string) ipn.LoginProfileView {
	out := pm.matchingProfiles(uid, func(p ipn.LoginProfileView) bool {
		return p.Name() == name && pm.checkProfileAccessAs(uid, p) == nil
	})
	if len(out) == 0 {
		return ipn.LoginProfileView{}
	}
	if len(out) > 1 {
		pm.logf("[unexpected] multiple profiles with the same name")
	}
	return out[0]
}

func (pm *profileManager) findProfileByKey(uid ipn.WindowsUserID, key ipn.StateKey) ipn.LoginProfileView {
	out := pm.matchingProfiles(uid, func(p ipn.LoginProfileView) bool {
		return p.Key() == key && pm.checkProfileAccessAs(uid, p) == nil
	})
	if len(out) == 0 {
		return ipn.LoginProfileView{}
	}
	if len(out) > 1 {
		pm.logf("[unexpected] multiple profiles with the same key")
	}
	return out[0]
}

func (pm *profileManager) setUnattendedModeAsConfigured() error {
	if pm.goos != "windows" {
		return nil
	}

	if pm.currentProfile.Key() != "" && pm.prefs.ForceDaemon() {
		return pm.WriteState(ipn.ServerModeStartKey, []byte(pm.currentProfile.Key()))
	} else {
		return pm.WriteState(ipn.ServerModeStartKey, nil)
	}
}

// SetPrefs sets the current profile's prefs to the provided value.
// It also saves the prefs to the [ipn.StateStore]. It stores a copy of the
// provided prefs, which may be accessed via [profileManager.CurrentPrefs].
//
// The [ipn.NetworkProfile] stores additional information about the tailnet the user
// is logged into so that we can keep track of things like their domain name
// across user switches to disambiguate the same account but a different tailnet.
func (pm *profileManager) SetPrefs(prefsIn ipn.PrefsView, np ipn.NetworkProfile) error {
	cp := pm.currentProfile
	if persist := prefsIn.Persist(); !persist.Valid() || persist.NodeID() == "" || persist.UserProfile().LoginName == "" {
		// We don't know anything about this profile, so ignore it for now.
		return pm.setProfilePrefsNoPermCheck(pm.currentProfile, prefsIn.AsStruct().View())
	}

	// Check if we already have an existing profile that matches the user/node.
	if existing := pm.findMatchingProfiles(pm.currentUserID, prefsIn); len(existing) > 0 {
		// We already have a profile for this user/node we should reuse it. Also
		// cleanup any other duplicate profiles.
		cp = existing[0]
		existing = existing[1:]
		for _, p := range existing {
			// Clear the state.
			if err := pm.store.WriteState(p.Key(), nil); err != nil {
				// We couldn't delete the state, so keep the profile around.
				continue
			}
			// Remove the profile, knownProfiles will be persisted
			// in [profileManager.setProfilePrefs] below.
			delete(pm.knownProfiles, p.ID())
		}
	}
	// TODO(nickkhyl): Revisit how we handle implicit switching to a different profile,
	// which occurs when prefsIn represents a node/user different from that of the
	// currentProfile. It happens when a login (either reauth or user-initiated login)
	// is completed with a different node/user identity than the one currently in use.
	//
	// Currently, we overwrite the existing profile prefs with the ones from prefsIn,
	// where prefsIn is the previous profile's prefs with an updated Persist, LoggedOut,
	// WantRunning and possibly other fields. This may not be the desired behavior.
	//
	// Additionally, LocalBackend doesn't treat it as a proper profile switch,
	// meaning that [LocalBackend.resetForProfileChangeLocked] is not called and
	// certain node/profile-specific state may not be reset as expected.
	//
	// However, [profileManager] notifies [ipnext.Extension]s about the profile change,
	// so features migrated from LocalBackend to external packages should not be affected.
	//
	// See tailscale/corp#28014.
	if !cp.Equals(pm.currentProfile) {
		const sameNode = false // implicit profile switch
		pm.currentProfile = cp
		pm.prefs = prefsIn.AsStruct().View()
		if f := pm.StateChangeHook; f != nil {
			f(cp, prefsIn, sameNode)
		}
		pm.extHost.NotifyProfileChange(cp, prefsIn, sameNode)
	}
	cp, err := pm.setProfilePrefs(nil, prefsIn, np)
	if err != nil {
		return err
	}
	return pm.setProfileAsUserDefault(cp)
}

// setProfilePrefs is like [profileManager.SetPrefs], but sets prefs for the specified [ipn.LoginProfile],
// returning a read-only view of the updated profile on success. If the specified profile is nil,
// it defaults to the current profile. If the profile is not accessible by the current user,
// the method returns an [errProfileAccessDenied].
func (pm *profileManager) setProfilePrefs(lp *ipn.LoginProfile, prefsIn ipn.PrefsView, np ipn.NetworkProfile) (ipn.LoginProfileView, error) {
	isCurrentProfile := lp == nil || (lp.ID != "" && lp.ID == pm.currentProfile.ID())
	if isCurrentProfile {
		lp = pm.CurrentProfile().AsStruct()
	}

	if err := pm.checkProfileAccess(lp.View()); err != nil {
		return ipn.LoginProfileView{}, err
	}

	// An empty profile.ID indicates that the profile is new, the node info wasn't available,
	// and it hasn't been persisted yet. We'll generate both an ID and [ipn.StateKey]
	// once the information is available and needs to be persisted.
	if lp.ID == "" {
		if persist := prefsIn.Persist(); persist.Valid() && persist.NodeID() != "" && persist.UserProfile().LoginName != "" {
			// Generate an ID and [ipn.StateKey] now that we have the node info.
			lp.ID, lp.Key = newUnusedID(pm.knownProfiles)
		}

		// Set the current user as the profile owner, unless the current user ID does
		// not represent a specific user, or the profile is already owned by a different user.
		// It is only relevant on Windows where we have a multi-user system.
		if lp.LocalUserID == "" && pm.currentUserID != "" {
			lp.LocalUserID = pm.currentUserID
		}
	}

	var up tailcfg.UserProfile
	if persist := prefsIn.Persist(); persist.Valid() {
		up = persist.UserProfile()
		if up.DisplayName == "" {
			up.DisplayName = up.LoginName
		}
		lp.NodeID = persist.NodeID()
	} else {
		lp.NodeID = ""
	}

	if prefsIn.ProfileName() != "" {
		lp.Name = prefsIn.ProfileName()
	} else {
		lp.Name = up.LoginName
	}
	lp.ControlURL = prefsIn.ControlURL()
	lp.UserProfile = up
	lp.NetworkProfile = np

	// Update the current profile view to reflect the changes
	// if the specified profile is the current profile.
	if isCurrentProfile {
		// Always set pm.currentProfile to the new profile view for pointer equality.
		// We check it further down the call stack.
		lp := lp.View()
		sameProfileInfo := lp.Equals(pm.currentProfile)
		pm.currentProfile = lp
		if !sameProfileInfo {
			// But only invoke the callbacks if the profile info has actually changed.
			const sameNode = true                // just an info update; still the same node
			pm.prefs = prefsIn.AsStruct().View() // suppress further callbacks for this change
			if f := pm.StateChangeHook; f != nil {
				f(lp, prefsIn, sameNode)
			}
			pm.extHost.NotifyProfileChange(lp, prefsIn, sameNode)
		}
	}

	// An empty profile.ID indicates that the node info is not available yet,
	// and the profile doesn't need to be saved on disk.
	if lp.ID != "" {
		pm.knownProfiles[lp.ID] = lp.View()
		if err := pm.writeKnownProfiles(); err != nil {
			return ipn.LoginProfileView{}, err
		}
		// Clone prefsIn and create a read-only view as a safety measure to
		// prevent accidental preference mutations, both externally and internally.
		if err := pm.setProfilePrefsNoPermCheck(lp.View(), prefsIn.AsStruct().View()); err != nil {
			return ipn.LoginProfileView{}, err
		}
	}
	return lp.View(), nil
}

func newUnusedID(knownProfiles map[ipn.ProfileID]ipn.LoginProfileView) (ipn.ProfileID, ipn.StateKey) {
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

// setProfilePrefsNoPermCheck sets the profile's prefs to the provided value.
// If the profile has the [ipn.LoginProfile.Key] set, it saves the prefs to the
// [ipn.StateStore] under that key. It returns an error if the profile is non-current
// and does not have its Key set, or if the prefs could not be saved.
// The method does not perform any additional checks on the specified
// profile, such as verifying the caller's access rights or checking
// if another profile for the same node already exists.
func (pm *profileManager) setProfilePrefsNoPermCheck(profile ipn.LoginProfileView, clonedPrefs ipn.PrefsView) error {
	isCurrentProfile := pm.currentProfile == profile
	if isCurrentProfile {
		oldPrefs := pm.prefs
		pm.prefs = clonedPrefs

		// Sadly, profile prefs can be changed in multiple ways.  It's pretty
		// chaotic, and in many cases callers use unexported methods of the
		// profile manager instead of going through [LocalBackend.setPrefsLocked]
		// or at least using [profileManager.SetPrefs].
		//
		// While we should definitely clean this up to improve
		// the overall structure of how prefs are set, which would
		// also address current and future conflicts, such as
		// competing features changing the same prefs, this method
		// is currently the central place where we can detect all
		// changes to the current profile's prefs.
		//
		// That said, regardless of the cleanup, we might want
		// to keep the profileManager responsible for invoking
		// profile- and prefs-related callbacks.

		if !clonedPrefs.Equals(oldPrefs) {
			if f := pm.StateChangeHook; f != nil {
				f(pm.currentProfile, clonedPrefs, true)
			}
			pm.extHost.NotifyProfilePrefsChanged(pm.currentProfile, oldPrefs, clonedPrefs)
		}

		pm.updateHealth()
	}
	if profile.Key() != "" {
		if err := pm.writePrefsToStore(profile.Key(), clonedPrefs); err != nil {
			return err
		}
	} else if !isCurrentProfile {
		return errors.New("cannot set prefs for a non-current in-memory profile")
	}
	if isCurrentProfile {
		return pm.setUnattendedModeAsConfigured()
	}
	return nil
}

// setPrefsNoPermCheck is like [profileManager.setProfilePrefsNoPermCheck], but sets the current profile's prefs.
func (pm *profileManager) setPrefsNoPermCheck(clonedPrefs ipn.PrefsView) error {
	return pm.setProfilePrefsNoPermCheck(pm.currentProfile, clonedPrefs)
}

func (pm *profileManager) writePrefsToStore(key ipn.StateKey, prefs ipn.PrefsView) error {
	if key == "" {
		return nil
	}
	if err := pm.WriteState(key, prefs.ToBytes()); err != nil {
		pm.logf("WriteState(%q): %v", key, err)
		return err
	}
	return nil
}

// Profiles returns the list of known profiles accessible to the current user.
func (pm *profileManager) Profiles() []ipn.LoginProfileView {
	return pm.allProfilesFor(pm.currentUserID)
}

// ProfileByID returns a profile with the given id, if it is accessible to the current user.
// If the profile exists but is not accessible to the current user, it returns an [errProfileAccessDenied].
// If the profile does not exist, it returns an [errProfileNotFound].
func (pm *profileManager) ProfileByID(id ipn.ProfileID) (ipn.LoginProfileView, error) {
	kp, err := pm.profileByIDNoPermCheck(id)
	if err != nil {
		return ipn.LoginProfileView{}, err
	}
	if err := pm.checkProfileAccess(kp); err != nil {
		return ipn.LoginProfileView{}, err
	}
	return kp, nil
}

// profileByIDNoPermCheck is like [profileManager.ProfileByID], but it doesn't
// check user's access rights to the profile.
func (pm *profileManager) profileByIDNoPermCheck(id ipn.ProfileID) (ipn.LoginProfileView, error) {
	if id == pm.currentProfile.ID() {
		return pm.currentProfile, nil
	}
	kp, ok := pm.knownProfiles[id]
	if !ok {
		return ipn.LoginProfileView{}, errProfileNotFound
	}
	return kp, nil
}

// ProfilePrefs returns preferences for a profile with the given id.
// If the profile exists but is not accessible to the current user, it returns an [errProfileAccessDenied].
// If the profile does not exist, it returns an [errProfileNotFound].
func (pm *profileManager) ProfilePrefs(id ipn.ProfileID) (ipn.PrefsView, error) {
	kp, err := pm.profileByIDNoPermCheck(id)
	if err != nil {
		return ipn.PrefsView{}, errProfileNotFound
	}
	if err := pm.checkProfileAccess(kp); err != nil {
		return ipn.PrefsView{}, err
	}
	return pm.profilePrefs(kp)
}

func (pm *profileManager) profilePrefs(p ipn.LoginProfileView) (ipn.PrefsView, error) {
	if p.ID() == pm.currentProfile.ID() {
		return pm.prefs, nil
	}
	return pm.loadSavedPrefs(p.Key())
}

// SwitchToProfileByID switches to the profile with the given id.
// It returns the current profile and whether the call resulted in a profile change.
// If the profile exists but is not accessible to the current user, it returns an [errProfileAccessDenied].
// If the profile does not exist, it returns an [errProfileNotFound].
func (pm *profileManager) SwitchToProfileByID(id ipn.ProfileID) (_ ipn.LoginProfileView, changed bool, err error) {
	if id == pm.currentProfile.ID() {
		return pm.currentProfile, false, nil
	}
	profile, err := pm.ProfileByID(id)
	if err != nil {
		return pm.currentProfile, false, err
	}
	return pm.SwitchToProfile(profile)
}

// SwitchToDefaultProfileForUser switches to the default (last used) profile for the specified user.
// It creates a new one and switches to it if the specified user does not have a default profile,
// or returns an error if the default profile is inaccessible or could not be loaded.
func (pm *profileManager) SwitchToDefaultProfileForUser(uid ipn.WindowsUserID) (_ ipn.LoginProfileView, changed bool, err error) {
	return pm.SwitchToProfile(pm.DefaultUserProfile(uid))
}

// SwitchToDefaultProfile is like [profileManager.SwitchToDefaultProfileForUser], but switches
// to the default profile for the current user.
func (pm *profileManager) SwitchToDefaultProfile() (_ ipn.LoginProfileView, changed bool, err error) {
	return pm.SwitchToDefaultProfileForUser(pm.currentUserID)
}

// setProfileAsUserDefault sets the specified profile as the default for the current user.
// It returns an [errProfileAccessDenied] if the specified profile is not accessible to the current user.
func (pm *profileManager) setProfileAsUserDefault(profile ipn.LoginProfileView) error {
	if profile.Key() == "" {
		// The profile has not been persisted yet; ignore it for now.
		return nil
	}
	if err := pm.checkProfileAccess(profile); err != nil {
		return errProfileAccessDenied
	}
	k := ipn.CurrentProfileKey(string(pm.currentUserID))
	return pm.WriteState(k, []byte(profile.Key()))
}

func (pm *profileManager) loadSavedPrefs(key ipn.StateKey) (ipn.PrefsView, error) {
	bs, err := pm.store.ReadState(key)
	if err == ipn.ErrStateNotExist || len(bs) == 0 {
		return defaultPrefs, nil
	}
	if err != nil {
		return ipn.PrefsView{}, err
	}
	savedPrefs := ipn.NewPrefs()
	if err := ipn.PrefsFromBytes(bs, savedPrefs); err != nil {
		return ipn.PrefsView{}, fmt.Errorf("parsing saved prefs: %v", err)
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
	// Before
	// https://github.com/tailscale/tailscale/pull/11814/commits/1613b18f8280c2bce786980532d012c9f0454fa2#diff-314ba0d799f70c8998940903efb541e511f352b39a9eeeae8d475c921d66c2ac
	// prefs could set AutoUpdate.Apply=true via EditPrefs or tailnet
	// auto-update defaults. After that change, such value is "invalid" and
	// cause any EditPrefs calls to fail (other than disabling auto-updates).
	//
	// Reset AutoUpdate.Apply if we detect such invalid prefs.
	if savedPrefs.AutoUpdate.Apply.EqualBool(true) && !clientupdate.CanAutoUpdate() {
		savedPrefs.AutoUpdate.Apply.Clear()
	}

	return savedPrefs.View(), nil
}

// CurrentProfile returns a read-only [ipn.LoginProfileView] of the current profile.
// The value may be zero if the profile is not persisted.
func (pm *profileManager) CurrentProfile() ipn.LoginProfileView {
	return pm.currentProfile
}

// errProfileNotFound is returned by methods that accept a ProfileID
// when the specified profile does not exist.
var errProfileNotFound = errors.New("profile not found")

// errProfileAccessDenied is returned by methods that accept a ProfileID
// when the current user does not have access to the specified profile.
// It is used temporarily until we implement access checks based on the
// caller's identity in tailscale/corp#18342.
var errProfileAccessDenied = errors.New("profile access denied")

// DeleteProfile removes the profile with the given id. It returns
// [errProfileNotFound] if the profile does not exist, or an
// [errProfileAccessDenied] if the specified profile is not accessible
// to the current user.
// If the profile is the current profile, it is the equivalent of
// calling [profileManager.NewProfile] followed by [profileManager.DeleteProfile](id).
// This is useful for deleting the last profile. In other cases, it is
// recommended to call [profileManager.SwitchProfile] first.
func (pm *profileManager) DeleteProfile(id ipn.ProfileID) error {
	if id == pm.currentProfile.ID() {
		return pm.deleteCurrentProfile()
	}
	kp, ok := pm.knownProfiles[id]
	if !ok {
		return errProfileNotFound
	}
	if err := pm.checkProfileAccess(kp); err != nil {
		return err
	}
	return pm.deleteProfileNoPermCheck(kp)
}

func (pm *profileManager) deleteCurrentProfile() error {
	if err := pm.checkProfileAccess(pm.currentProfile); err != nil {
		return err
	}
	if pm.currentProfile.ID() == "" {
		// Deleting the in-memory only new profile, just create a new one.
		pm.SwitchToNewProfile()
		return nil
	}
	return pm.deleteProfileNoPermCheck(pm.currentProfile)
}

// deleteProfileNoPermCheck is like [profileManager.DeleteProfile],
// but it doesn't check user's access rights to the profile.
func (pm *profileManager) deleteProfileNoPermCheck(profile ipn.LoginProfileView) error {
	if profile.ID() == pm.currentProfile.ID() {
		pm.SwitchToNewProfile()
	}
	if err := pm.WriteState(profile.Key(), nil); err != nil {
		return err
	}
	delete(pm.knownProfiles, profile.ID())
	metricDeleteProfile.Add(1)
	return pm.writeKnownProfiles()
}

// DeleteAllProfilesForUser removes all known profiles accessible to the current user
// and switches to a new, empty profile.
func (pm *profileManager) DeleteAllProfilesForUser() error {
	metricDeleteAllProfile.Add(1)

	currentProfileDeleted := false
	writeKnownProfiles := func() error {
		if currentProfileDeleted || pm.currentProfile.ID() == "" {
			pm.SwitchToNewProfile()
		}
		return pm.writeKnownProfiles()
	}

	for _, kp := range pm.knownProfiles {
		if pm.checkProfileAccess(kp) != nil {
			// Skip profiles we don't have access to.
			continue
		}
		if err := pm.WriteState(kp.Key(), nil); err != nil {
			// Write to remove references to profiles we've already deleted, but
			// return the original error.
			writeKnownProfiles()
			return err
		}
		delete(pm.knownProfiles, kp.ID())
		if kp.ID() == pm.currentProfile.ID() {
			currentProfileDeleted = true
		}
	}
	return writeKnownProfiles()
}

func (pm *profileManager) writeKnownProfiles() error {
	b, err := json.Marshal(pm.knownProfiles)
	if err != nil {
		return err
	}
	metricProfileCount.Set(int64(len(pm.knownProfiles)))
	return pm.WriteState(ipn.KnownProfilesStateKey, b)
}

func (pm *profileManager) updateHealth() {
	if !pm.prefs.Valid() {
		return
	}
	pm.health.SetAutoUpdatePrefs(pm.prefs.AutoUpdate().Check, pm.prefs.AutoUpdate().Apply)
}

// SwitchToNewProfile creates and switches to a new unnamed profile. The new profile is
// not persisted until [profileManager.SetPrefs] is called with a logged-in user.
func (pm *profileManager) SwitchToNewProfile() {
	pm.SwitchToNewProfileForUser(pm.currentUserID)
}

// SwitchToNewProfileForUser is like [profileManager.SwitchToNewProfile], but it switches to the
// specified user and sets that user as the profile owner for the new profile.
func (pm *profileManager) SwitchToNewProfileForUser(uid ipn.WindowsUserID) {
	pm.SwitchToProfile(pm.NewProfileForUser(uid))
}

// zeroProfile is a read-only view of a new, empty profile that is not persisted to the store.
var zeroProfile = (&ipn.LoginProfile{}).View()

// NewProfileForUser creates a new profile for the specified user and returns a read-only view of it.
// It neither switches to the new profile nor persists it to the store.
func (pm *profileManager) NewProfileForUser(uid ipn.WindowsUserID) ipn.LoginProfileView {
	return (&ipn.LoginProfile{LocalUserID: uid}).View()
}

// defaultPrefs is the default prefs for a new profile. This initializes before
// even this package's init() so do not rely on other parts of the system being
// fully initialized here (for example, syspolicy will not be available on
// Apple platforms).
var defaultPrefs = func() ipn.PrefsView {
	prefs := ipn.NewPrefs()
	prefs.LoggedOut = true
	prefs.WantRunning = false

	return prefs.View()
}()

// Store returns the [ipn.StateStore] used by the [profileManager].
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
	ht := new(health.Tracker) // in tests, don't care about the health status
	pm, err := newProfileManager(store, logf, ht)
	if err != nil {
		return ipn.PrefsView{}, err
	}
	return pm.CurrentPrefs(), nil
}

// newProfileManager creates a new [profileManager] using the provided [ipn.StateStore].
// It also loads the list of known profiles from the store.
func newProfileManager(store ipn.StateStore, logf logger.Logf, health *health.Tracker) (*profileManager, error) {
	return newProfileManagerWithGOOS(store, logf, health, envknob.GOOS())
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

func readKnownProfiles(store ipn.StateStore) (map[ipn.ProfileID]ipn.LoginProfileView, error) {
	var knownProfiles map[ipn.ProfileID]ipn.LoginProfileView
	prfB, err := store.ReadState(ipn.KnownProfilesStateKey)
	switch err {
	case nil:
		if err := json.Unmarshal(prfB, &knownProfiles); err != nil {
			return nil, fmt.Errorf("unmarshaling known profiles: %w", err)
		}
	case ipn.ErrStateNotExist:
		knownProfiles = make(map[ipn.ProfileID]ipn.LoginProfileView)
	default:
		return nil, fmt.Errorf("calling ReadState on state store: %w", err)
	}
	return knownProfiles, nil
}

func newProfileManagerWithGOOS(store ipn.StateStore, logf logger.Logf, ht *health.Tracker, goos string) (*profileManager, error) {
	logf = logger.WithPrefix(logf, "pm: ")
	stateKey, err := readAutoStartKey(store, goos)
	if err != nil {
		return nil, err
	}

	knownProfiles, err := readKnownProfiles(store)
	if err != nil {
		return nil, err
	}

	metricProfileCount.Set(int64(len(knownProfiles)))

	pm := &profileManager{
		goos:          goos,
		store:         store,
		knownProfiles: knownProfiles,
		logf:          logf,
		health:        ht,
	}

	var initialProfile ipn.LoginProfileView
	if stateKey != "" {
		initialProfile = pm.findProfileByKey("", stateKey)
		// Most platform behavior is controlled by the goos parameter, however
		// some behavior is implied by build tag and fails when run on Windows,
		// so we explicitly avoid that behavior when running on Windows.
		// Specifically this reaches down into legacy preference loading that is
		// specialized by profiles_windows.go and fails in tests on an invalid
		// uid passed in from the unix tests. The uid's used for Windows tests
		// and runtime must be valid Windows security identifier structures.
	} else if len(knownProfiles) == 0 && goos != "windows" && runtime.GOOS != "windows" {
		// No known profiles, try a migration.
		pm.dlogf("no known profiles; trying to migrate from legacy prefs")
		if initialProfile, err = pm.migrateFromLegacyPrefs(pm.currentUserID); err != nil {

		}
	}
	if !initialProfile.Valid() {
		var initialUserID ipn.WindowsUserID
		if suf, ok := strings.CutPrefix(string(stateKey), "user-"); ok {
			initialUserID = ipn.WindowsUserID(suf)
		}
		initialProfile = pm.NewProfileForUser(initialUserID)
	}
	if _, _, err := pm.SwitchToProfile(initialProfile); err != nil {
		return nil, err
	}
	return pm, nil
}

func (pm *profileManager) migrateFromLegacyPrefs(uid ipn.WindowsUserID) (ipn.LoginProfileView, error) {
	metricMigration.Add(1)
	sentinel, prefs, err := pm.loadLegacyPrefs(uid)
	if err != nil {
		metricMigrationError.Add(1)
		return ipn.LoginProfileView{}, fmt.Errorf("load legacy prefs: %w", err)
	}
	pm.dlogf("loaded legacy preferences; sentinel=%q", sentinel)
	profile, err := pm.setProfilePrefs(&ipn.LoginProfile{LocalUserID: uid}, prefs, ipn.NetworkProfile{})
	if err != nil {
		metricMigrationError.Add(1)
		return ipn.LoginProfileView{}, fmt.Errorf("migrating _daemon profile: %w", err)
	}
	pm.completeMigration(sentinel)
	pm.dlogf("completed legacy preferences migration with sentinel=%q", sentinel)
	metricMigrationSuccess.Add(1)
	return profile, nil
}

func (pm *profileManager) requiresBackfill() bool {
	return pm != nil &&
		pm.currentProfile.Valid() &&
		pm.currentProfile.NetworkProfile().RequiresBackfill()
}

var (
	metricNewProfile       = clientmetric.NewCounter("profiles_new")
	metricSwitchProfile    = clientmetric.NewCounter("profiles_switch")
	metricDeleteProfile    = clientmetric.NewCounter("profiles_delete")
	metricDeleteAllProfile = clientmetric.NewCounter("profiles_delete_all")
	metricProfileCount     = clientmetric.NewGauge("profiles_count")

	metricMigration        = clientmetric.NewCounter("profiles_migration")
	metricMigrationError   = clientmetric.NewCounter("profiles_migration_error")
	metricMigrationSuccess = clientmetric.NewCounter("profiles_migration_success")
)
