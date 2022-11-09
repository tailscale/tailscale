// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/strs"
)

type loginProfile struct {
	ID   string
	Name string
	Key  ipn.StateKey

	// LocalUserID is the user ID of the user who created this profile.
	// It is only relevant on Windows where we have a multi-user system.
	LocalUserID string
}

// ProfileManager is a wrapper around a StateStore that manages
// multiple profiles and the current profile.
type ProfileManager struct {
	store ipn.StateStore
	logf  logger.Logf

	// Lock order: LocalBackend.mu, then pm.mu.
	mu             sync.Mutex               // guards following
	currentUserID  string                   // only used on Windows
	knownProfiles  map[string]*loginProfile // key is profile name
	currentProfile *loginProfile
	prefs          ipn.PrefsView
	isNewProfile   bool
}

// CurrentUser returns the current user ID. It is only non-empty on
// Windows where we have a multi-user system.
func (pm *ProfileManager) CurrentUser() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.currentUserID
}

// SetCurrentUser sets the current user ID. The uid is only non-empty
// on Windows where we have a multi-user system.
func (pm *ProfileManager) SetCurrentUser(uid string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.currentUserID == uid {
		return nil
	}
	cpk := ipn.CurrentProfileKey(uid)
	if b, err := pm.store.ReadState(cpk); err == nil {
		pk := ipn.StateKey(string(b))
		prefs, err := pm.loadSavedPrefs(pk)
		if err != nil {
			return err
		}
		pm.currentProfile = pm.findProfileByKey(pk)
		pm.prefs = prefs
		pm.isNewProfile = false
	} else if err == ipn.ErrStateNotExist {
		pm.prefs = emptyPrefs
		pm.isNewProfile = true
	} else {
		return err
	}
	pm.currentUserID = uid
	return nil
}

func (pm *ProfileManager) findProfileByKey(key ipn.StateKey) *loginProfile {
	for _, p := range pm.knownProfiles {
		if p.Key == key {
			return p
		}
	}
	return nil
}

func (pm *ProfileManager) setUnattendedModeAsConfigured() error {
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
func (pm *ProfileManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.prefs = emptyPrefs
	pm.currentUserID = ""
	pm.currentProfile = nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randID() string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// SetPrefs sets the current profile's prefs to the provided value.
// It also saves the prefs to the StateStore. It stores a copy of the
// provided prefs, which may be accessed via CurrentPrefs.
func (pm *ProfileManager) SetPrefs(prefsIn ipn.PrefsView) error {
	prefs := prefsIn.AsStruct().View()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	ps := prefs.Persist()
	if !pm.isNewProfile || ps == nil || ps.LoginName == "" {
		return pm.setPrefsLocked(prefs)
	}
	id, k := newUnusedKey(pm.knownProfiles)
	pm.currentProfile = &loginProfile{
		Name:        ps.LoginName,
		Key:         k,
		ID:          id,
		LocalUserID: pm.currentUserID,
	}
	pm.knownProfiles[ps.LoginName] = pm.currentProfile
	if err := pm.writeKnownProfiles(); err != nil {
		delete(pm.knownProfiles, ps.LoginName)
		return err
	}
	if err := pm.setAsUserSelectedProfileLocked(); err != nil {
		return err
	}
	if err := pm.setPrefsLocked(prefs); err != nil {
		return err
	}
	pm.isNewProfile = false
	return nil
}

func newUnusedKey(knownProfiles map[string]*loginProfile) (id string, key ipn.StateKey) {
keyGenLoop:
	for {
		id := randID()
		for _, kp := range knownProfiles {
			if kp.ID == id {
				continue keyGenLoop
			}
		}
		return id, ipn.StateKey("profile-" + id)
	}
}

func (pm *ProfileManager) setPrefsLocked(clonedPrefs ipn.PrefsView) error {
	pm.prefs = clonedPrefs
	if pm.currentProfile == nil {
		return nil
	}
	if err := pm.writePrefsToStore(pm.currentProfile.Key, pm.prefs); err != nil {
		return err
	}
	return pm.setUnattendedModeAsConfigured()
}

func (pm *ProfileManager) writePrefsToStore(key ipn.StateKey, prefs ipn.PrefsView) error {
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
func (pm *ProfileManager) Profiles() []string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	var profiles []string
	for _, p := range pm.knownProfiles {
		if p.LocalUserID == pm.currentUserID {
			profiles = append(profiles, p.Name)
		}
	}
	return profiles
}

// SwitchProfile switches to the profile with the given name.
func (pm *ProfileManager) SwitchProfile(profile string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	kp, ok := pm.knownProfiles[profile]
	if !ok {
		return fmt.Errorf("profile %q not found", profile)
	}

	if pm.currentProfile != nil && kp.Key == pm.currentProfile.Key && pm.prefs.Valid() {
		return nil
	}
	if kp.LocalUserID != pm.currentUserID {
		return fmt.Errorf("profile %q is not owned by current user", profile)
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

func (pm *ProfileManager) setAsUserSelectedProfileLocked() error {
	k := ipn.CurrentProfileKey(pm.currentUserID)
	if pm.currentProfile == nil {
		return pm.store.WriteState(k, nil)
	}
	return pm.store.WriteState(k, []byte(pm.currentProfile.Key))
}

func (pm *ProfileManager) loadSavedPrefs(key ipn.StateKey) (ipn.PrefsView, error) {
	bs, err := pm.store.ReadState(key)
	if err != nil {
		if err == ipn.ErrStateNotExist {
			return emptyPrefs, nil
		}
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

// CurrentProfile returns the name and ID of the current profile, or "" if the profile
// is not named.
func (pm *ProfileManager) CurrentProfile() (name string, id string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.currentProfile == nil {
		return "", ""
	}
	return pm.currentProfile.Name, pm.currentProfile.ID
}

// DeleteProfile removes the profile with the given name. It is a no-op if the
// profile does not exist.
func (pm *ProfileManager) DeleteProfile(profile string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	kp, ok := pm.knownProfiles[profile]
	if !ok {
		return nil
	}
	if kp.Key == pm.currentProfile.Key {
		return fmt.Errorf("cannot remove current profile")
	}
	if err := pm.store.WriteState(kp.Key, nil); err != nil {
		return err
	}
	delete(pm.knownProfiles, profile)
	return pm.writeKnownProfiles()
}

func (pm *ProfileManager) writeKnownProfiles() error {
	b, err := json.Marshal(pm.knownProfiles)
	if err != nil {
		return err
	}
	return pm.store.WriteState(ipn.KnownProfilesStateKey, b)
}

// NewProfile creates a new profile with the given name. It switches to the new
// profile. The new profile is not persisted until SetPrefs is called.
func (pm *ProfileManager) NewProfile() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.prefs = emptyPrefs
	pm.currentProfile = nil
	pm.isNewProfile = true
}

// emptyPrefs is the default prefs for a new profile.
var emptyPrefs = func() ipn.PrefsView {
	prefs := ipn.NewPrefs()
	prefs.WantRunning = false
	return prefs.View()
}()

// Store returns the StateStore used by the ProfileManager.
func (pm *ProfileManager) Store() ipn.StateStore {
	return pm.store
}

// CurrentPrefs returns a read-only view of the current prefs.
func (pm *ProfileManager) CurrentPrefs() ipn.PrefsView {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.prefs
}

// NewProfileManager creates a new ProfileManager using the provided StateStore.
// It also loads the list of known profiles from the StateStore.
// If a state key is provided, it will be used to load the current profile.
func NewProfileManager(store ipn.StateStore, logf logger.Logf, stateKey ipn.StateKey) (*ProfileManager, error) {
	return newProfileManagerWithGOOS(store, logf, stateKey, runtime.GOOS)
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

func readKnownProfiles(store ipn.StateStore) (map[string]*loginProfile, error) {
	var knownProfiles map[string]*loginProfile
	prfB, err := store.ReadState(ipn.KnownProfilesStateKey)
	switch err {
	case nil:
		if err := json.Unmarshal(prfB, &knownProfiles); err != nil {
			return nil, fmt.Errorf("unmarshaling known profiles: %w", err)
		}
	case ipn.ErrStateNotExist:
		knownProfiles = make(map[string]*loginProfile)
	default:
		return nil, fmt.Errorf("calling ReadState on state store: %w", err)
	}
	return knownProfiles, nil
}

func newProfileManagerWithGOOS(store ipn.StateStore, logf logger.Logf, stateKey ipn.StateKey, goos string) (*ProfileManager, error) {
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

	pm := &ProfileManager{
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
				pm.currentUserID = suf
			}
			pm.isNewProfile = true
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
		pm.prefs = emptyPrefs
	}

	return pm, nil
}

func (pm *ProfileManager) migrateFromLegacyPrefs() error {
	pm.NewProfile()
	k := ipn.GlobalDaemonStateKey
	switch runtime.GOOS {
	case "ios", "darwin":
		k = "ipn-go-bridge"
	}
	prefs, err := pm.loadSavedPrefs(k)
	if err != nil {
		return fmt.Errorf("calling ReadState on state store: %w", err)
	}
	pm.logf("migrating %q profile to new format", k)
	if err := pm.SetPrefs(prefs); err != nil {
		return fmt.Errorf("migrating _daemon profile: %w", err)
	}
	// Do not delete the old state key, as we may be downgraded to an
	// older version that still relies on it.
	return nil
}
