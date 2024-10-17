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
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
)

var debug = envknob.RegisterBool("TS_DEBUG_PROFILES")

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
	knownProfiles  map[ipn.ProfileID]*ipn.LoginProfile // always non-nil
	currentProfile *ipn.LoginProfile                   // always non-nil
	prefs          ipn.PrefsView                       // always Valid.
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
	pm.currentUserID = uid
	if err := pm.SwitchToDefaultProfile(); err != nil {
		// SetCurrentUserID should never fail and must always switch to the
		// user's default profile or create a new profile for the current user.
		// Until we implement multi-user support and the new permission model,
		// and remove the concept of the "current user" completely, we must ensure
		// that when SetCurrentUserID exits, the profile in pm.currentProfile
		// is either an existing profile owned by the user, or a new, empty profile.
		pm.logf("%q's default profile cannot be used; creating a new one: %v", uid, err)
		pm.NewProfileForUser(uid)
	}
}

// DefaultUserProfileID returns [ipn.ProfileID] of the default (last used) profile for the specified user,
// or an empty string if the specified user does not have a default profile.
func (pm *profileManager) DefaultUserProfileID(uid ipn.WindowsUserID) ipn.ProfileID {
	// Read the CurrentProfileKey from the store which stores
	// the selected profile for the specified user.
	b, err := pm.store.ReadState(ipn.CurrentProfileKey(string(uid)))
	pm.dlogf("DefaultUserProfileID: ReadState(%q) = %v, %v", string(uid), len(b), err)
	if err == ipn.ErrStateNotExist || len(b) == 0 {
		if runtime.GOOS == "windows" {
			pm.dlogf("DefaultUserProfileID: windows: migrating from legacy preferences")
			profile, err := pm.migrateFromLegacyPrefs(uid, false)
			if err == nil {
				return profile.ID
			}
			pm.logf("failed to migrate from legacy preferences: %v", err)
		}
		return ""
	}

	pk := ipn.StateKey(string(b))
	prof := pm.findProfileByKey(pk)
	if prof == nil {
		pm.dlogf("DefaultUserProfileID: no profile found for key: %q", pk)
		return ""
	}
	return prof.ID
}

// checkProfileAccess returns an [errProfileAccessDenied] if the current user
// does not have access to the specified profile.
func (pm *profileManager) checkProfileAccess(profile *ipn.LoginProfile) error {
	if pm.currentUserID != "" && profile.LocalUserID != pm.currentUserID {
		return errProfileAccessDenied
	}
	return nil
}

// allProfiles returns all profiles accessible to the current user.
// The returned profiles are sorted by Name.
func (pm *profileManager) allProfiles() (out []*ipn.LoginProfile) {
	for _, p := range pm.knownProfiles {
		if pm.checkProfileAccess(p) == nil {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *ipn.LoginProfile) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}

// matchingProfiles is like [profileManager.allProfiles], but returns only profiles
// matching the given predicate.
func (pm *profileManager) matchingProfiles(f func(*ipn.LoginProfile) bool) (out []*ipn.LoginProfile) {
	all := pm.allProfiles()
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
func (pm *profileManager) findMatchingProfiles(prefs ipn.PrefsView) []*ipn.LoginProfile {
	return pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.ControlURL == prefs.ControlURL() &&
			(p.UserProfile.ID == prefs.Persist().UserProfile().ID ||
				p.NodeID == prefs.Persist().NodeID())
	})
}

// ProfileIDForName returns the profile ID for the profile with the
// given name. It returns "" if no such profile exists among profiles
// accessible to the current user.
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
		pm.logf("[unexpected] multiple profiles with the same name")
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
		pm.logf("[unexpected] multiple profiles with the same key")
	}
	return out[0]
}

func (pm *profileManager) setUnattendedModeAsConfigured() error {
	if pm.goos != "windows" {
		return nil
	}

	if pm.currentProfile.Key != "" && pm.prefs.ForceDaemon() {
		return pm.WriteState(ipn.ServerModeStartKey, []byte(pm.currentProfile.Key))
	} else {
		return pm.WriteState(ipn.ServerModeStartKey, nil)
	}
}

// Reset unloads the current profile, if any.
func (pm *profileManager) Reset() {
	pm.currentUserID = ""
	pm.NewProfile()
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
	if existing := pm.findMatchingProfiles(prefsIn); len(existing) > 0 {
		// We already have a profile for this user/node we should reuse it. Also
		// cleanup any other duplicate profiles.
		cp = existing[0]
		existing = existing[1:]
		for _, p := range existing {
			// Clear the state.
			if err := pm.store.WriteState(p.Key, nil); err != nil {
				// We couldn't delete the state, so keep the profile around.
				continue
			}
			// Remove the profile, knownProfiles will be persisted
			// in [profileManager.setProfilePrefs] below.
			delete(pm.knownProfiles, p.ID)
		}
	}
	pm.currentProfile = cp
	if err := pm.SetProfilePrefs(cp, prefsIn, np); err != nil {
		return err
	}
	return pm.setProfileAsUserDefault(cp)

}

// SetProfilePrefs is like [profileManager.SetPrefs], but sets prefs for the specified [ipn.LoginProfile]
// which is not necessarily the [profileManager.CurrentProfile]. It returns an [errProfileAccessDenied]
// if the specified profile is not accessible by the current user.
func (pm *profileManager) SetProfilePrefs(lp *ipn.LoginProfile, prefsIn ipn.PrefsView, np ipn.NetworkProfile) error {
	if err := pm.checkProfileAccess(lp); err != nil {
		return err
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

	// An empty profile.ID indicates that the node info is not available yet,
	// and the profile doesn't need to be saved on disk.
	if lp.ID != "" {
		pm.knownProfiles[lp.ID] = lp
		if err := pm.writeKnownProfiles(); err != nil {
			return err
		}
		// Clone prefsIn and create a read-only view as a safety measure to
		// prevent accidental preference mutations, both externally and internally.
		if err := pm.setProfilePrefsNoPermCheck(lp, prefsIn.AsStruct().View()); err != nil {
			return err
		}
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

// setProfilePrefsNoPermCheck sets the profile's prefs to the provided value.
// If the profile has the [ipn.LoginProfile.Key] set, it saves the prefs to the
// [ipn.StateStore] under that key. It returns an error if the profile is non-current
// and does not have its Key set, or if the prefs could not be saved.
// The method does not perform any additional checks on the specified
// profile, such as verifying the caller's access rights or checking
// if another profile for the same node already exists.
func (pm *profileManager) setProfilePrefsNoPermCheck(profile *ipn.LoginProfile, clonedPrefs ipn.PrefsView) error {
	isCurrentProfile := pm.currentProfile == profile
	if isCurrentProfile {
		pm.prefs = clonedPrefs
		pm.updateHealth()
	}
	if profile.Key != "" {
		if err := pm.writePrefsToStore(profile.Key, clonedPrefs); err != nil {
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
func (pm *profileManager) Profiles() []ipn.LoginProfile {
	allProfiles := pm.allProfiles()
	out := make([]ipn.LoginProfile, len(allProfiles))
	for i, p := range allProfiles {
		out[i] = *p
	}
	return out
}

// ProfileByID returns a profile with the given id, if it is accessible to the current user.
// If the profile exists but is not accessible to the current user, it returns an [errProfileAccessDenied].
// If the profile does not exist, it returns an [errProfileNotFound].
func (pm *profileManager) ProfileByID(id ipn.ProfileID) (ipn.LoginProfile, error) {
	kp, err := pm.profileByIDNoPermCheck(id)
	if err != nil {
		return ipn.LoginProfile{}, err
	}
	if err := pm.checkProfileAccess(kp); err != nil {
		return ipn.LoginProfile{}, err
	}
	return *kp, nil
}

// profileByIDNoPermCheck is like [profileManager.ProfileByID], but it doesn't
// check user's access rights to the profile.
func (pm *profileManager) profileByIDNoPermCheck(id ipn.ProfileID) (*ipn.LoginProfile, error) {
	if id == pm.currentProfile.ID {
		return pm.currentProfile, nil
	}
	kp, ok := pm.knownProfiles[id]
	if !ok {
		return nil, errProfileNotFound
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

func (pm *profileManager) profilePrefs(p *ipn.LoginProfile) (ipn.PrefsView, error) {
	if p.ID == pm.currentProfile.ID {
		return pm.prefs, nil
	}
	return pm.loadSavedPrefs(p.Key)
}

// SwitchProfile switches to the profile with the given id.
// If the profile exists but is not accessible to the current user, it returns an [errProfileAccessDenied].
// If the profile does not exist, it returns an [errProfileNotFound].
func (pm *profileManager) SwitchProfile(id ipn.ProfileID) error {
	metricSwitchProfile.Add(1)

	kp, ok := pm.knownProfiles[id]
	if !ok {
		return errProfileNotFound
	}
	if pm.currentProfile != nil && kp.ID == pm.currentProfile.ID && pm.prefs.Valid() {
		return nil
	}

	if err := pm.checkProfileAccess(kp); err != nil {
		return fmt.Errorf("%w: profile %q is not accessible to the current user", err, id)
	}
	prefs, err := pm.loadSavedPrefs(kp.Key)
	if err != nil {
		return err
	}
	pm.prefs = prefs
	pm.updateHealth()
	pm.currentProfile = kp
	return pm.setProfileAsUserDefault(kp)
}

// SwitchToDefaultProfile switches to the default (last used) profile for the current user.
// It creates a new one and switches to it if the current user does not have a default profile,
// or returns an error if the default profile is inaccessible or could not be loaded.
func (pm *profileManager) SwitchToDefaultProfile() error {
	if id := pm.DefaultUserProfileID(pm.currentUserID); id != "" {
		return pm.SwitchProfile(id)
	}
	pm.NewProfileForUser(pm.currentUserID)
	return nil
}

// setProfileAsUserDefault sets the specified profile as the default for the current user.
// It returns an [errProfileAccessDenied] if the specified profile is not accessible to the current user.
func (pm *profileManager) setProfileAsUserDefault(profile *ipn.LoginProfile) error {
	if profile.Key == "" {
		// The profile has not been persisted yet; ignore it for now.
		return nil
	}
	if err := pm.checkProfileAccess(profile); err != nil {
		return errProfileAccessDenied
	}
	k := ipn.CurrentProfileKey(string(pm.currentUserID))
	return pm.WriteState(k, []byte(profile.Key))
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

// CurrentProfile returns the current LoginProfile.
// The value may be zero if the profile is not persisted.
func (pm *profileManager) CurrentProfile() ipn.LoginProfile {
	return *pm.currentProfile
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
	metricDeleteProfile.Add(1)
	if id == pm.currentProfile.ID {
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
	if pm.currentProfile.ID == "" {
		// Deleting the in-memory only new profile, just create a new one.
		pm.NewProfile()
		return nil
	}
	return pm.deleteProfileNoPermCheck(pm.currentProfile)
}

// deleteProfileNoPermCheck is like [profileManager.DeleteProfile],
// but it doesn't check user's access rights to the profile.
func (pm *profileManager) deleteProfileNoPermCheck(profile *ipn.LoginProfile) error {
	if profile.ID == pm.currentProfile.ID {
		pm.NewProfile()
	}
	if err := pm.WriteState(profile.Key, nil); err != nil {
		return err
	}
	delete(pm.knownProfiles, profile.ID)
	return pm.writeKnownProfiles()
}

// DeleteAllProfilesForUser removes all known profiles accessible to the current user
// and switches to a new, empty profile.
func (pm *profileManager) DeleteAllProfilesForUser() error {
	metricDeleteAllProfile.Add(1)

	currentProfileDeleted := false
	writeKnownProfiles := func() error {
		if currentProfileDeleted || pm.currentProfile.ID == "" {
			pm.NewProfile()
		}
		return pm.writeKnownProfiles()
	}

	for _, kp := range pm.knownProfiles {
		if pm.checkProfileAccess(kp) != nil {
			// Skip profiles we don't have access to.
			continue
		}
		if err := pm.WriteState(kp.Key, nil); err != nil {
			// Write to remove references to profiles we've already deleted, but
			// return the original error.
			writeKnownProfiles()
			return err
		}
		delete(pm.knownProfiles, kp.ID)
		if kp.ID == pm.currentProfile.ID {
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
	return pm.WriteState(ipn.KnownProfilesStateKey, b)
}

func (pm *profileManager) updateHealth() {
	if !pm.prefs.Valid() {
		return
	}
	pm.health.SetAutoUpdatePrefs(pm.prefs.AutoUpdate().Check, pm.prefs.AutoUpdate().Apply)
}

// NewProfile creates and switches to a new unnamed profile. The new profile is
// not persisted until [profileManager.SetPrefs] is called with a logged-in user.
func (pm *profileManager) NewProfile() {
	pm.NewProfileForUser(pm.currentUserID)
}

// NewProfileForUser is like [profileManager.NewProfile], but it switches to the
// specified user and sets that user as the profile owner for the new profile.
func (pm *profileManager) NewProfileForUser(uid ipn.WindowsUserID) {
	pm.currentUserID = uid

	metricNewProfile.Add(1)

	pm.prefs = defaultPrefs
	pm.updateHealth()
	pm.currentProfile = &ipn.LoginProfile{LocalUserID: uid}
}

// newProfileWithPrefs creates a new profile with the specified prefs and assigns
// the specified uid as the profile owner. If switchNow is true, it switches to the
// newly created profile immediately. It returns the newly created profile on success,
// or an error on failure.
func (pm *profileManager) newProfileWithPrefs(uid ipn.WindowsUserID, prefs ipn.PrefsView, switchNow bool) (*ipn.LoginProfile, error) {
	metricNewProfile.Add(1)

	profile := &ipn.LoginProfile{LocalUserID: uid}
	if err := pm.SetProfilePrefs(profile, prefs, ipn.NetworkProfile{}); err != nil {
		return nil, err
	}
	if switchNow {
		pm.currentProfile = profile
		pm.prefs = prefs.AsStruct().View()
		pm.updateHealth()
		if err := pm.setProfileAsUserDefault(profile); err != nil {
			return nil, err
		}
	}
	return profile, nil
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

	pm := &profileManager{
		goos:          goos,
		store:         store,
		knownProfiles: knownProfiles,
		logf:          logf,
		health:        ht,
	}

	if stateKey != "" {
		for _, v := range knownProfiles {
			if v.Key == stateKey {
				pm.currentProfile = v
			}
		}
		if pm.currentProfile == nil {
			if suf, ok := strings.CutPrefix(string(stateKey), "user-"); ok {
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
		if err := pm.setProfilePrefsNoPermCheck(pm.currentProfile, prefs); err != nil {
			return nil, err
		}
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
		if _, err := pm.migrateFromLegacyPrefs(pm.currentUserID, true); err != nil {
			return nil, err
		}
	} else {
		pm.NewProfile()
	}

	return pm, nil
}

func (pm *profileManager) migrateFromLegacyPrefs(uid ipn.WindowsUserID, switchNow bool) (*ipn.LoginProfile, error) {
	metricMigration.Add(1)
	sentinel, prefs, err := pm.loadLegacyPrefs(uid)
	if err != nil {
		metricMigrationError.Add(1)
		return nil, fmt.Errorf("load legacy prefs: %w", err)
	}
	pm.dlogf("loaded legacy preferences; sentinel=%q", sentinel)
	profile, err := pm.newProfileWithPrefs(uid, prefs, switchNow)
	if err != nil {
		metricMigrationError.Add(1)
		return nil, fmt.Errorf("migrating _daemon profile: %w", err)
	}
	pm.completeMigration(sentinel)
	pm.dlogf("completed legacy preferences migration with sentinel=%q", sentinel)
	metricMigrationSuccess.Add(1)
	return profile, nil
}

func (pm *profileManager) requiresBackfill() bool {
	return pm != nil &&
		pm.currentProfile != nil &&
		pm.currentProfile.NetworkProfile.RequiresBackfill()
}

var (
	metricNewProfile       = clientmetric.NewCounter("profiles_new")
	metricSwitchProfile    = clientmetric.NewCounter("profiles_switch")
	metricDeleteProfile    = clientmetric.NewCounter("profiles_delete")
	metricDeleteAllProfile = clientmetric.NewCounter("profiles_delete_all")

	metricMigration        = clientmetric.NewCounter("profiles_migration")
	metricMigrationError   = clientmetric.NewCounter("profiles_migration_error")
	metricMigrationSuccess = clientmetric.NewCounter("profiles_migration_success")
)
