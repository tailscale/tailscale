// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"slices"
	"strings"

	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
)

var errAlreadyMigrated = errors.New("profile migration already completed")

var debug = envknob.RegisterBool("TS_DEBUG_PROFILES")

// profileManager is a wrapper around a StateStore that manages
// multiple profiles and the current profile.
//
// It is not safe for concurrent use.
type profileManager struct {
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
	pm.dlogf("SetCurrentUserID: ReadState(%q) = %v, %v", string(uid), len(b), err)
	if err == ipn.ErrStateNotExist || len(b) == 0 {
		if runtime.GOOS == "windows" {
			pm.dlogf("SetCurrentUserID: windows: migrating from legacy preferences")
			if err := pm.migrateFromLegacyPrefs(); err != nil && !errors.Is(err, errAlreadyMigrated) {
				return err
			}
		} else {
			pm.NewProfile()
		}
		return nil
	}

	// Now attempt to load the profile using the key we just read.
	pk := ipn.StateKey(string(b))
	prof := pm.findProfileByKey(pk)
	if prof == nil {
		pm.dlogf("SetCurrentUserID: no profile found for key: %q", pk)
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
	pm.updateHealth()
	return nil
}

// allProfiles returns all profiles that belong to the currentUserID.
// The returned profiles are sorted by Name.
func (pm *profileManager) allProfiles() (out []*ipn.LoginProfile) {
	for _, p := range pm.knownProfiles {
		if p.LocalUserID == pm.currentUserID {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *ipn.LoginProfile) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}

// matchingProfiles returns all profiles that match the given predicate and
// belong to the currentUserID.
// The returned profiles are sorted by Name.
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

// findMatchinProfiles returns all profiles that represent the same node/user as
// prefs.
// The returned profiles are sorted by Name.
func (pm *profileManager) findMatchingProfiles(prefs *ipn.Prefs) []*ipn.LoginProfile {
	return pm.matchingProfiles(func(p *ipn.LoginProfile) bool {
		return p.ControlURL == prefs.ControlURL &&
			(p.UserProfile.ID == prefs.Persist.UserProfile.ID ||
				p.NodeID == prefs.Persist.NodeID)
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
// It also saves the prefs to the StateStore. It stores a copy of the
// provided prefs, which may be accessed via CurrentPrefs.
//
// NetworkProfile stores additional information about the tailnet the user
// is logged into so that we can keep track of things like their domain name
// across user switches to disambiguate the same account but a different tailnet.
func (pm *profileManager) SetPrefs(prefsIn ipn.PrefsView, np ipn.NetworkProfile) error {
	prefs := prefsIn.AsStruct()
	newPersist := prefs.Persist
	if newPersist == nil || newPersist.NodeID == "" || newPersist.UserProfile.LoginName == "" {
		// We don't know anything about this profile, so ignore it for now.
		return pm.setPrefsLocked(prefs.View())
	}
	up := newPersist.UserProfile
	if up.DisplayName == "" {
		up.DisplayName = up.LoginName
	}
	cp := pm.currentProfile
	// Check if we already have an existing profile that matches the user/node.
	if existing := pm.findMatchingProfiles(prefs); len(existing) > 0 {
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
			// Remove the profile, knownProfiles will be persisted below.
			delete(pm.knownProfiles, p.ID)
		}
	} else if cp.ID == "" {
		// We didn't have an existing profile, so create a new one.
		cp.ID, cp.Key = newUnusedID(pm.knownProfiles)
		cp.LocalUserID = pm.currentUserID
	} else {
		// This means that there was a force-reauth as a new node that
		// we haven't seen before.
	}

	if prefs.ProfileName != "" {
		cp.Name = prefs.ProfileName
	} else {
		cp.Name = up.LoginName
	}
	cp.ControlURL = prefs.ControlURL
	cp.UserProfile = newPersist.UserProfile
	cp.NodeID = newPersist.NodeID
	cp.NetworkProfile = np
	pm.knownProfiles[cp.ID] = cp
	pm.currentProfile = cp
	if err := pm.writeKnownProfiles(); err != nil {
		return err
	}
	if err := pm.setAsUserSelectedProfileLocked(); err != nil {
		return err
	}
	if err := pm.setPrefsLocked(prefs.View()); err != nil {
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
	pm.updateHealth()
	if pm.currentProfile.ID == "" {
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
	if err := pm.WriteState(key, prefs.ToBytes()); err != nil {
		pm.logf("WriteState(%q): %v", key, err)
		return err
	}
	return nil
}

// Profiles returns the list of known profiles.
func (pm *profileManager) Profiles() []ipn.LoginProfile {
	allProfiles := pm.allProfiles()
	out := make([]ipn.LoginProfile, 0, len(allProfiles))
	for _, p := range allProfiles {
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
	pm.updateHealth()
	pm.currentProfile = kp
	return pm.setAsUserSelectedProfileLocked()
}

func (pm *profileManager) setAsUserSelectedProfileLocked() error {
	k := ipn.CurrentProfileKey(string(pm.currentUserID))
	return pm.WriteState(k, []byte(pm.currentProfile.Key))
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

	if id == "" {
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
	if err := pm.WriteState(kp.Key, nil); err != nil {
		return err
	}
	delete(pm.knownProfiles, id)
	return pm.writeKnownProfiles()
}

// DeleteAllProfiles removes all known profiles and switches to a new empty
// profile.
func (pm *profileManager) DeleteAllProfiles() error {
	metricDeleteAllProfile.Add(1)

	for _, kp := range pm.knownProfiles {
		if err := pm.WriteState(kp.Key, nil); err != nil {
			// Write to remove references to profiles we've already deleted, but
			// return the original error.
			pm.writeKnownProfiles()
			return err
		}
		delete(pm.knownProfiles, kp.ID)
	}
	pm.NewProfile()
	return pm.writeKnownProfiles()
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
	pm.health.SetCheckForUpdates(pm.prefs.AutoUpdate().Check)
}

// NewProfile creates and switches to a new unnamed profile. The new profile is
// not persisted until SetPrefs is called with a logged-in user.
func (pm *profileManager) NewProfile() {
	metricNewProfile.Add(1)

	pm.prefs = defaultPrefs
	pm.updateHealth()
	pm.currentProfile = &ipn.LoginProfile{}
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
	ht := new(health.Tracker) // in tests, don't care about the health status
	pm, err := newProfileManager(store, logf, ht)
	if err != nil {
		return ipn.PrefsView{}, err
	}
	return pm.CurrentPrefs(), nil
}

// newProfileManager creates a new ProfileManager using the provided StateStore.
// It also loads the list of known profiles from the StateStore.
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
		if err := pm.setPrefsLocked(prefs); err != nil {
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
	sentinel, prefs, err := pm.loadLegacyPrefs()
	if err != nil {
		metricMigrationError.Add(1)
		return fmt.Errorf("load legacy prefs: %w", err)
	}
	pm.dlogf("loaded legacy preferences; sentinel=%q", sentinel)
	if err := pm.SetPrefs(prefs, ipn.NetworkProfile{}); err != nil {
		metricMigrationError.Add(1)
		return fmt.Errorf("migrating _daemon profile: %w", err)
	}
	pm.completeMigration(sentinel)
	pm.dlogf("completed legacy preferences migration with sentinel=%q", sentinel)
	metricMigrationSuccess.Add(1)
	return nil
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
