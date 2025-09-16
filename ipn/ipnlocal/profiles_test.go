// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/clientupdate"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
)

func TestProfileCurrentUserSwitch(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	newProfile := func(t *testing.T, loginName string) ipn.PrefsView {
		id++
		t.Helper()
		pm.SwitchToNewProfile()
		p := pm.CurrentPrefs().AsStruct()
		p.Persist = &persist.Persist{
			NodeID:         tailcfg.StableNodeID(fmt.Sprint(id)),
			PrivateNodeKey: key.NewNode(),
			UserProfile: tailcfg.UserProfile{
				ID:        tailcfg.UserID(id),
				LoginName: loginName,
			},
		}
		if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		return p.View()
	}

	pm.SetCurrentUserID("user1")
	newProfile(t, "user1")
	cp := pm.currentProfile
	pm.DeleteProfile(cp.ID())
	if !pm.currentProfile.Valid() {
		t.Fatal("currentProfile is nil")
	} else if pm.currentProfile.ID() != "" {
		t.Fatalf("currentProfile.ID = %q, want empty", pm.currentProfile.ID())
	}
	if !pm.CurrentPrefs().Equals(defaultPrefs) {
		t.Fatalf("CurrentPrefs() = %v, want emptyPrefs", pm.CurrentPrefs().Pretty())
	}

	pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	pm.SetCurrentUserID("user1")
	if !pm.currentProfile.Valid() {
		t.Fatal("currentProfile is nil")
	} else if pm.currentProfile.ID() != "" {
		t.Fatalf("currentProfile.ID = %q, want empty", pm.currentProfile.ID())
	}
	if !pm.CurrentPrefs().Equals(defaultPrefs) {
		t.Fatalf("CurrentPrefs() = %v, want emptyPrefs", pm.CurrentPrefs().Pretty())
	}
}

func TestProfileList(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	newProfile := func(t *testing.T, loginName string) ipn.PrefsView {
		id++
		t.Helper()
		pm.SwitchToNewProfile()
		p := pm.CurrentPrefs().AsStruct()
		p.Persist = &persist.Persist{
			NodeID:         tailcfg.StableNodeID(fmt.Sprint(id)),
			PrivateNodeKey: key.NewNode(),
			UserProfile: tailcfg.UserProfile{
				ID:        tailcfg.UserID(id),
				LoginName: loginName,
			},
		}
		if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		return p.View()
	}
	checkProfiles := func(t *testing.T, want ...string) {
		t.Helper()
		got := pm.Profiles()
		if len(got) != len(want) {
			t.Fatalf("got %d profiles, want %d", len(got), len(want))
		}
		for i, w := range want {
			if got[i].Name() != w {
				t.Errorf("got profile %d name %q, want %q", i, got[i].Name(), w)
			}
		}
	}

	pm.SetCurrentUserID("user1")
	newProfile(t, "alice")
	newProfile(t, "bob")
	checkProfiles(t, "alice", "bob")

	pm.SetCurrentUserID("user2")
	checkProfiles(t)
	newProfile(t, "carol")
	carol := pm.currentProfile
	checkProfiles(t, "carol")

	pm.SetCurrentUserID("user1")
	checkProfiles(t, "alice", "bob")
	if lp := pm.findProfileByKey("user1", carol.Key()); lp.Valid() {
		t.Fatalf("found profile for user2 in user1's profile list")
	}
	if lp := pm.findProfileByName("user1", carol.Name()); lp.Valid() {
		t.Fatalf("found profile for user2 in user1's profile list")
	}

	pm.SetCurrentUserID("user2")
	checkProfiles(t, "carol")
}

func TestProfileDupe(t *testing.T) {
	newPersist := func(user, node int) *persist.Persist {
		return &persist.Persist{
			NodeID: tailcfg.StableNodeID(fmt.Sprintf("node%d", node)),
			UserProfile: tailcfg.UserProfile{
				ID:        tailcfg.UserID(user),
				LoginName: fmt.Sprintf("user%d@example.com", user),
			},
		}
	}
	user1Node1 := newPersist(1, 1)
	user1Node2 := newPersist(1, 2)
	user2Node1 := newPersist(2, 1)
	user2Node2 := newPersist(2, 2)
	user3Node3 := newPersist(3, 3)

	reauth := func(pm *profileManager, p *persist.Persist) {
		prefs := ipn.NewPrefs()
		prefs.Persist = p
		must.Do(pm.SetPrefs(prefs.View(), ipn.NetworkProfile{}))
	}
	login := func(pm *profileManager, p *persist.Persist) {
		pm.SwitchToNewProfile()
		reauth(pm, p)
	}

	type step struct {
		fn func(pm *profileManager, p *persist.Persist)
		p  *persist.Persist
	}

	tests := []struct {
		name  string
		steps []step
		profs []*persist.Persist
	}{
		{
			name: "reauth-new-node",
			steps: []step{
				{login, user1Node1},
				{reauth, user3Node3},
			},
			profs: []*persist.Persist{
				user3Node3,
			},
		},
		{
			name: "reauth-same-node",
			steps: []step{
				{login, user1Node1},
				{reauth, user1Node1},
			},
			profs: []*persist.Persist{
				user1Node1,
			},
		},
		{
			name: "reauth-other-profile",
			steps: []step{
				{login, user1Node1},
				{login, user2Node2},
				{reauth, user1Node1},
			},
			profs: []*persist.Persist{
				user1Node1,
				user2Node2,
			},
		},
		{
			name: "reauth-replace-user",
			steps: []step{
				{login, user1Node1},
				{login, user3Node3},
				{reauth, user2Node1},
			},
			profs: []*persist.Persist{
				user2Node1,
				user3Node3,
			},
		},
		{
			name: "reauth-replace-node",
			steps: []step{
				{login, user1Node1},
				{login, user3Node3},
				{reauth, user1Node2},
			},
			profs: []*persist.Persist{
				user1Node2,
				user3Node3,
			},
		},
		{
			name: "login-same-node",
			steps: []step{
				{login, user1Node1},
				{login, user3Node3}, // random other profile
				{login, user1Node1},
			},
			profs: []*persist.Persist{
				user1Node1,
				user3Node3,
			},
		},
		{
			name: "login-replace-user",
			steps: []step{
				{login, user1Node1},
				{login, user3Node3}, // random other profile
				{login, user2Node1},
			},
			profs: []*persist.Persist{
				user2Node1,
				user3Node3,
			},
		},
		{
			name: "login-replace-node",
			steps: []step{
				{login, user1Node1},
				{login, user3Node3}, // random other profile
				{login, user1Node2},
			},
			profs: []*persist.Persist{
				user1Node2,
				user3Node3,
			},
		},
		{
			name: "login-new-node",
			steps: []step{
				{login, user1Node1},
				{login, user2Node2},
			},
			profs: []*persist.Persist{
				user1Node1,
				user2Node2,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := new(mem.Store)
			pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tc.steps {
				s.fn(pm, s.p)
			}
			profs := pm.Profiles()
			var got []*persist.Persist
			for _, p := range profs {
				prefs, err := pm.loadSavedPrefs(p.Key())
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, prefs.Persist().AsStruct())
			}
			d := cmp.Diff(tc.profs, got, cmpopts.SortSlices(func(a, b *persist.Persist) bool {
				if a.NodeID != b.NodeID {
					return a.NodeID < b.NodeID
				}
				return a.UserProfile.ID < b.UserProfile.ID
			}))
			if d != "" {
				t.Fatal(d)
			}
		})
	}
}

// TestProfileManagement tests creating, loading, and switching profiles.
func TestProfileManagement(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile := ""
	wantProfiles := map[string]ipn.PrefsView{
		"": defaultPrefs,
	}
	checkProfiles := func(t *testing.T) {
		t.Helper()
		prof := pm.CurrentProfile()
		t.Logf("\tCurrentProfile = %q", prof.Name())
		if prof.Name() != wantCurProfile {
			t.Fatalf("CurrentProfile = %q; want %q", prof.Name(), wantCurProfile)
		}
		profiles := pm.Profiles()
		wantLen := len(wantProfiles)
		if _, ok := wantProfiles[""]; ok {
			wantLen--
		}
		if len(profiles) != wantLen {
			t.Fatalf("Profiles = %v; want %v", profiles, wantProfiles)
		}
		p := pm.CurrentPrefs()
		t.Logf("\tCurrentPrefs = %s", p.Pretty())
		if !p.Valid() {
			t.Fatalf("CurrentPrefs = %v; want valid", p)
		}
		if !p.Equals(wantProfiles[wantCurProfile]) {
			t.Fatalf("CurrentPrefs = %v; want %v", p.Pretty(), wantProfiles[wantCurProfile].Pretty())
		}
		for _, p := range profiles {
			got, err := pm.loadSavedPrefs(p.Key())
			if err != nil {
				t.Fatal(err)
			}
			// Use Hostname as a proxy for all prefs.
			if !got.Equals(wantProfiles[p.Name()]) {
				t.Fatalf("Prefs for profile %q =\n got=%+v\nwant=%v", p.Name(), got.Pretty(), wantProfiles[p.Name()].Pretty())
			}
		}
	}
	logins := make(map[string]tailcfg.UserID)
	nodeIDs := make(map[string]tailcfg.StableNodeID)
	setPrefs := func(t *testing.T, loginName string) ipn.PrefsView {
		t.Helper()
		p := pm.CurrentPrefs().AsStruct()
		uid := logins[loginName]
		if uid.IsZero() {
			uid = tailcfg.UserID(len(logins) + 1)
			logins[loginName] = uid
		}
		nid := nodeIDs[loginName]
		if nid.IsZero() {
			nid = tailcfg.StableNodeID(fmt.Sprint(len(nodeIDs) + 1))
			nodeIDs[loginName] = nid
		}
		p.Persist = &persist.Persist{
			PrivateNodeKey: key.NewNode(),
			UserProfile: tailcfg.UserProfile{
				ID:        uid,
				LoginName: loginName,
			},
			NodeID: nid,
		}
		if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		return p.View()
	}
	t.Logf("Check initial state from empty store")
	checkProfiles(t)

	{
		t.Logf("Set prefs for default profile")
		wantProfiles["user@1.example.com"] = setPrefs(t, "user@1.example.com")
		wantCurProfile = "user@1.example.com"
		delete(wantProfiles, "")
	}
	checkProfiles(t)

	t.Logf("Create new profile")
	pm.SwitchToNewProfile()
	wantCurProfile = ""
	wantProfiles[""] = defaultPrefs
	checkProfiles(t)

	{
		t.Logf("Set prefs for test profile")
		wantProfiles["user@2.example.com"] = setPrefs(t, "user@2.example.com")
		wantCurProfile = "user@2.example.com"
		delete(wantProfiles, "")
	}
	checkProfiles(t)

	t.Logf("Recreate profile manager from store")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	t.Logf("Delete default profile")
	if err := pm.DeleteProfile(pm.ProfileIDForName("user@1.example.com")); err != nil {
		t.Fatal(err)
	}
	delete(wantProfiles, "user@1.example.com")
	checkProfiles(t)

	t.Logf("Recreate profile manager from store after deleting default profile")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	t.Logf("Create new profile - 2")
	pm.SwitchToNewProfile()
	wantCurProfile = ""
	wantProfiles[""] = defaultPrefs
	checkProfiles(t)

	t.Logf("Login with the existing profile")
	wantProfiles["user@2.example.com"] = setPrefs(t, "user@2.example.com")
	delete(wantProfiles, "")
	wantCurProfile = "user@2.example.com"
	checkProfiles(t)

	t.Logf("Tag the current the profile")
	nodeIDs["tagged-node.2.ts.net"] = nodeIDs["user@2.example.com"]
	wantProfiles["tagged-node.2.ts.net"] = setPrefs(t, "tagged-node.2.ts.net")
	delete(wantProfiles, "user@2.example.com")
	wantCurProfile = "tagged-node.2.ts.net"
	checkProfiles(t)

	t.Logf("Relogin")
	wantProfiles["user@2.example.com"] = setPrefs(t, "user@2.example.com")
	delete(wantProfiles, "tagged-node.2.ts.net")
	wantCurProfile = "user@2.example.com"
	checkProfiles(t)

	if !clientupdate.CanAutoUpdate() {
		t.Logf("Save an invalid AutoUpdate pref value")
		prefs := pm.CurrentPrefs().AsStruct()
		prefs.AutoUpdate.Apply.Set(true)
		if err := pm.SetPrefs(prefs.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		if !pm.CurrentPrefs().AutoUpdate().Apply.EqualBool(true) {
			t.Fatal("SetPrefs failed to save auto-update setting")
		}
		// Re-load profiles to trigger migration for invalid auto-update value.
		pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
		if err != nil {
			t.Fatal(err)
		}
		checkProfiles(t)
		if pm.CurrentPrefs().AutoUpdate().Apply.EqualBool(true) {
			t.Fatal("invalid auto-update setting persisted after reload")
		}
	}
}

// TestProfileManagementWindows tests going into and out of Unattended mode on
// Windows.
func TestProfileManagementWindows(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := ipn.WindowsUserID(u.Uid)

	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile := ""
	wantProfiles := map[string]ipn.PrefsView{
		"": defaultPrefs,
	}
	checkProfiles := func(t *testing.T) {
		t.Helper()
		prof := pm.CurrentProfile()
		t.Logf("\tCurrentProfile = %q", prof.Name())
		if prof.Name() != wantCurProfile {
			t.Fatalf("CurrentProfile = %q; want %q", prof.Name(), wantCurProfile)
		}
		if p := pm.CurrentPrefs(); !p.Equals(wantProfiles[wantCurProfile]) {
			t.Fatalf("CurrentPrefs = %+v; want %+v", p.Pretty(), wantProfiles[wantCurProfile].Pretty())
		}
	}
	logins := make(map[string]tailcfg.UserID)
	setPrefs := func(t *testing.T, loginName string, forceDaemon bool) ipn.PrefsView {
		id := logins[loginName]
		if id.IsZero() {
			id = tailcfg.UserID(len(logins) + 1)
			logins[loginName] = id
		}
		p := pm.CurrentPrefs().AsStruct()
		p.ForceDaemon = forceDaemon
		p.Persist = &persist.Persist{
			UserProfile: tailcfg.UserProfile{
				ID:        id,
				LoginName: loginName,
			},
			NodeID: tailcfg.StableNodeID(strconv.Itoa(int(id))),
		}
		if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		return p.View()
	}
	t.Logf("Check initial state from empty store")
	checkProfiles(t)

	{
		t.Logf("Set user1 as logged in user")
		pm.SetCurrentUserID(uid)
		checkProfiles(t)
		t.Logf("Save prefs for user1")
		wantProfiles["default"] = setPrefs(t, "default", false)
		wantCurProfile = "default"
	}
	checkProfiles(t)

	{
		t.Logf("Create new profile")
		pm.SwitchToNewProfile()
		wantCurProfile = ""
		wantProfiles[""] = defaultPrefs
		checkProfiles(t)

		t.Logf("Save as test profile")
		wantProfiles["test"] = setPrefs(t, "test", false)
		wantCurProfile = "test"
		checkProfiles(t)
	}

	t.Logf("Recreate profile manager from store, should reset prefs")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile = ""
	wantProfiles[""] = defaultPrefs
	checkProfiles(t)

	{
		t.Logf("Set user1 as current user")
		pm.SetCurrentUserID(uid)
		wantCurProfile = "test"
	}
	checkProfiles(t)
	{
		t.Logf("set unattended mode")
		wantProfiles["test"] = setPrefs(t, "test", true)
	}
	if pm.CurrentUserID() != uid {
		t.Fatalf("CurrentUserID = %q; want %q", pm.CurrentUserID(), uid)
	}

	// Recreate the profile manager to ensure that it starts with test profile.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "windows")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)
	if pm.CurrentUserID() != uid {
		t.Fatalf("CurrentUserID = %q; want %q", pm.CurrentUserID(), uid)
	}
}

// TestDefaultPrefs tests that defaultPrefs is just NewPrefs with
// LoggedOut=true (the Prefs we use before connecting to control). We shouldn't
// be putting any defaulting there, and instead put all defaults in NewPrefs.
func TestDefaultPrefs(t *testing.T) {
	p1 := ipn.NewPrefs()
	p1.LoggedOut = true
	p1.WantRunning = false
	p2 := defaultPrefs
	if !p1.View().Equals(p2) {
		t.Errorf("defaultPrefs is %s, want %s; defaultPrefs should only modify WantRunning and LoggedOut, all other defaults should be in ipn.NewPrefs.", p2.Pretty(), p1.Pretty())
	}
}

// mutPrefsFn is a function that mutates the prefs.
// Deserialization pre‑populates prefs with default (non‑zero) values.
// After saving prefs and reading them back, we may not get exactly what we set.
// For this reason, tests apply changes through a helper that mutates
// [ipn.NewPrefs] instead of hard‑coding expected values in each case.
type mutPrefsFn func(*ipn.Prefs)

type profileState struct {
	*ipn.LoginProfile
	mutPrefs mutPrefsFn
}

func (s *profileState) prefs() ipn.PrefsView {
	prefs := ipn.NewPrefs() // apply changes to the default prefs
	s.mutPrefs(prefs)
	return prefs.View()
}

type profileStateChange struct {
	*ipn.LoginProfile
	mutPrefs mutPrefsFn
	sameNode bool
}

func wantProfileChange(state profileState) profileStateChange {
	return profileStateChange{
		LoginProfile: state.LoginProfile,
		mutPrefs:     state.mutPrefs,
		sameNode:     false,
	}
}

func wantPrefsChange(state profileState) profileStateChange {
	return profileStateChange{
		LoginProfile: state.LoginProfile,
		mutPrefs:     state.mutPrefs,
		sameNode:     true,
	}
}

func makeDefaultPrefs(p *ipn.Prefs) { *p = *defaultPrefs.AsStruct() }

func makeKnownProfileState(id int, nameSuffix string, uid ipn.WindowsUserID, mutPrefs mutPrefsFn) profileState {
	lowerNameSuffix := strings.ToLower(nameSuffix)
	nid := "node-" + tailcfg.StableNodeID(lowerNameSuffix)
	up := tailcfg.UserProfile{
		ID:          tailcfg.UserID(id),
		LoginName:   fmt.Sprintf("user-%s@example.com", lowerNameSuffix),
		DisplayName: "User " + nameSuffix,
	}
	return profileState{
		LoginProfile: &ipn.LoginProfile{
			LocalUserID: uid,
			Name:        up.LoginName,
			ID:          ipn.ProfileID(fmt.Sprintf("%04X", id)),
			Key:         "profile-" + ipn.StateKey(nameSuffix),
			NodeID:      nid,
			UserProfile: up,
		},
		mutPrefs: func(p *ipn.Prefs) {
			p.Hostname = "Hostname-" + nameSuffix
			if mutPrefs != nil {
				mutPrefs(p) // apply any additional changes
			}
			p.Persist = &persist.Persist{NodeID: nid, UserProfile: up}
		},
	}
}

func TestProfileStateChangeCallback(t *testing.T) {
	t.Parallel()

	// A few well-known profiles to use in tests.
	emptyProfile := profileState{
		LoginProfile: &ipn.LoginProfile{},
		mutPrefs:     makeDefaultPrefs,
	}
	profile0000 := profileState{
		LoginProfile: &ipn.LoginProfile{ID: "0000", Key: "profile-0000"},
		mutPrefs:     makeDefaultPrefs,
	}
	profileA := makeKnownProfileState(0xA, "A", "", nil)
	profileB := makeKnownProfileState(0xB, "B", "", nil)
	profileC := makeKnownProfileState(0xC, "C", "", nil)

	aliceUserID := ipn.WindowsUserID("S-1-5-21-1-2-3-4")
	aliceEmptyProfile := profileState{
		LoginProfile: &ipn.LoginProfile{LocalUserID: aliceUserID},
		mutPrefs:     makeDefaultPrefs,
	}
	bobUserID := ipn.WindowsUserID("S-1-5-21-3-4-5-6")
	bobEmptyProfile := profileState{
		LoginProfile: &ipn.LoginProfile{LocalUserID: bobUserID},
		mutPrefs:     makeDefaultPrefs,
	}
	bobKnownProfile := makeKnownProfileState(0xB0B, "Bob", bobUserID, nil)

	tests := []struct {
		name          string
		initial       *profileState         // if non-nil, this is the initial profile and prefs to start wit
		knownProfiles []profileState        // known profiles we can switch to
		action        func(*profileManager) // action to take on the profile manager
		wantChanges   []profileStateChange  // expected state changes
	}{
		{
			name: "no-changes",
			action: func(*profileManager) {
				// do nothing
			},
			wantChanges: nil,
		},
		{
			name: "no-initial/new-profile",
			action: func(pm *profileManager) {
				// The profile manager is new and started with a new empty profile.
				// This should not trigger a state change callback.
				pm.SwitchToNewProfile()
			},
			wantChanges: nil,
		},
		{
			name: "no-initial/new-profile-for-user",
			action: func(pm *profileManager) {
				// But switching to a new profile for a specific user should trigger
				// a state change callback.
				pm.SwitchToNewProfileForUser(aliceUserID)
			},
			wantChanges: []profileStateChange{
				// We want a new empty profile (owned by the specified user)
				// and the default prefs.
				wantProfileChange(aliceEmptyProfile),
			},
		},
		{
			name:    "with-initial/new-profile",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// And so does switching to a new profile when the initial profile
				// is non-empty.
				pm.SwitchToNewProfile()
			},
			wantChanges: []profileStateChange{
				// We want a new empty profile and the default prefs.
				wantProfileChange(emptyProfile),
			},
		},
		{
			name:    "with-initial/new-profile/twice",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// If we switch to a new profile twice, we should only get one state change.
				pm.SwitchToNewProfile()
				pm.SwitchToNewProfile()
			},
			wantChanges: []profileStateChange{
				// We want a new empty profile and the default prefs.
				wantProfileChange(emptyProfile),
			},
		},
		{
			name:    "with-initial/new-profile-for-user/twice",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// Unless we switch to a new profile for a specific user,
				// in which case we should get a state change twice.
				pm.SwitchToNewProfileForUser(aliceUserID)
				pm.SwitchToNewProfileForUser(aliceUserID) // no change here
				pm.SwitchToNewProfileForUser(bobUserID)
			},
			wantChanges: []profileStateChange{
				// Both profiles are empty, but they are owned by different users.
				wantProfileChange(aliceEmptyProfile),
				wantProfileChange(bobEmptyProfile),
			},
		},
		{
			name:    "with-initial/new-profile/twice/with-prefs-change",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// Or unless we switch to a new profile, change the prefs,
				// then switch to a new profile again. Since the current
				// profile is not empty after the prefs change, we should
				// get state changes for all three actions.
				pm.SwitchToNewProfile()
				p := pm.CurrentPrefs().AsStruct()
				p.WantRunning = true
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
				pm.SwitchToNewProfile()
			},
			wantChanges: []profileStateChange{
				wantProfileChange(emptyProfile), // new empty profile
				wantPrefsChange(profileState{ // prefs change, same profile
					LoginProfile: &ipn.LoginProfile{},
					mutPrefs: func(p *ipn.Prefs) {
						*p = *defaultPrefs.AsStruct()
						p.WantRunning = true
					},
				}),
				wantProfileChange(emptyProfile), // new empty profile again
			},
		},
		{
			name:          "switch-to-profile/by-id",
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// Switching to a known profile by ID should trigger a state change callback.
				pm.SwitchToProfileByID(profileB.ID)
			},
			wantChanges: []profileStateChange{
				wantProfileChange(profileB),
			},
		},
		{
			name:          "switch-to-profile/by-id/non-existent",
			knownProfiles: []profileState{profileA, profileC}, // no profileB
			action: func(pm *profileManager) {
				// Switching to a non-existent profile should fail and not trigger a state change callback.
				pm.SwitchToProfileByID(profileB.ID)
			},
			wantChanges: []profileStateChange{},
		},
		{
			name:          "switch-to-profile/by-id/twice-same",
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// But only for the first switch.
				// The second switch to the same profile should not trigger a state change callback.
				pm.SwitchToProfileByID(profileB.ID)
				pm.SwitchToProfileByID(profileB.ID)
			},
			wantChanges: []profileStateChange{
				wantProfileChange(profileB),
			},
		},
		{
			name:          "switch-to-profile/by-id/many",
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// Same idea, but with multiple switches.
				pm.SwitchToProfileByID(profileB.ID) // switch to Profile-B
				pm.SwitchToProfileByID(profileB.ID) // then to Profile-B again (no change)
				pm.SwitchToProfileByID(profileC.ID) // then to Profile-C (change)
				pm.SwitchToProfileByID(profileA.ID) // then to Profile-A (change)
				pm.SwitchToProfileByID(profileB.ID) // then to Profile-B (change)
			},
			wantChanges: []profileStateChange{
				wantProfileChange(profileB),
				wantProfileChange(profileC),
				wantProfileChange(profileA),
				wantProfileChange(profileB),
			},
		},
		{
			name:          "switch-to-profile/by-view",
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// Switching to a known profile by an [ipn.LoginProfileView]
				// should also trigger a state change callback.
				pm.SwitchToProfile(profileB.View())
			},
			wantChanges: []profileStateChange{
				wantProfileChange(profileB),
			},
		},
		{
			name:    "switch-to-profile/by-view/empty",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// SwitchToProfile supports switching to an empty profile.
				emptyProfile := &ipn.LoginProfile{}
				pm.SwitchToProfile(emptyProfile.View())
			},
			wantChanges: []profileStateChange{
				wantProfileChange(emptyProfile),
			},
		},
		{
			name:          "switch-to-profile/by-view/non-existent",
			knownProfiles: []profileState{profileA, profileC},
			action: func(pm *profileManager) {
				// Switching to a an unknown profile by an [ipn.LoginProfileView]
				// should fail and not trigger a state change callback.
				pm.SwitchToProfile(profileB.View())
			},
			wantChanges: []profileStateChange{},
		},
		{
			name:    "switch-to-profile/by-view/empty-for-user",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// And switching to an empty profile for a specific user also works.
				pm.SwitchToProfile(bobEmptyProfile.View())
			},
			wantChanges: []profileStateChange{
				wantProfileChange(bobEmptyProfile),
			},
		},
		{
			name:    "switch-to-profile/by-view/invalid",
			initial: &profile0000,
			action: func(pm *profileManager) {
				// Switching to an invalid profile should create and switch
				// to a new empty profile.
				pm.SwitchToProfile(ipn.LoginProfileView{})
			},
			wantChanges: []profileStateChange{
				wantProfileChange(emptyProfile),
			},
		},
		{
			name:          "delete-profile/current",
			initial:       &profileA, // profileA is the current profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// Deleting the current profile should switch to a new empty profile.
				pm.DeleteProfile(profileA.ID)
			},
			wantChanges: []profileStateChange{
				wantProfileChange(emptyProfile),
			},
		},
		{
			name:          "delete-profile/current-with-user",
			initial:       &bobKnownProfile,
			knownProfiles: []profileState{profileA, profileB, profileC, bobKnownProfile},
			action: func(pm *profileManager) {
				// Similarly, deleting the current profile for a specific user should switch
				// to a new empty profile for that user (at least while the "current user"
				// is still a thing on Windows).
				pm.DeleteProfile(bobKnownProfile.ID)
			},
			wantChanges: []profileStateChange{
				wantProfileChange(bobEmptyProfile),
			},
		},
		{
			name:          "delete-profile/non-current",
			initial:       &profileA, // profileA is the current profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// But deleting a non-current profile should not trigger a state change callback.
				pm.DeleteProfile(profileB.ID)
			},
			wantChanges: []profileStateChange{},
		},
		{
			name:    "set-prefs/new-profile",
			initial: &emptyProfile, // the current profile is empty
			action: func(pm *profileManager) {
				// The current profile is new and empty, but we can still set p.
				// This should trigger a state change callback.
				p := pm.CurrentPrefs().AsStruct()
				p.WantRunning = true
				p.Hostname = "New-Hostname"
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
			},
			wantChanges: []profileStateChange{
				// Still an empty profile, but with new prefs.
				wantPrefsChange(profileState{
					LoginProfile: emptyProfile.LoginProfile,
					mutPrefs: func(p *ipn.Prefs) {
						*p = *emptyProfile.prefs().AsStruct()
						p.WantRunning = true
						p.Hostname = "New-Hostname"
					},
				}),
			},
		},
		{
			name:          "set-prefs/current-profile",
			initial:       &profileA, // profileA is the current profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				p := pm.CurrentPrefs().AsStruct()
				p.WantRunning = true
				p.Hostname = "New-Hostname"
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
			},
			wantChanges: []profileStateChange{
				wantPrefsChange(profileState{
					LoginProfile: profileA.LoginProfile, // same profile
					mutPrefs: func(p *ipn.Prefs) { // but with new prefs
						*p = *profileA.prefs().AsStruct()
						p.WantRunning = true
						p.Hostname = "New-Hostname"
					},
				}),
			},
		},
		{
			name:          "set-prefs/current-profile/profile-name",
			initial:       &profileA, // profileA is the current profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				p := pm.CurrentPrefs().AsStruct()
				p.ProfileName = "This is User A"
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
			},
			wantChanges: []profileStateChange{
				// Still the same profile, but with a new profile name
				// populated from the prefs. The prefs are also updated.
				wantPrefsChange(profileState{
					LoginProfile: func() *ipn.LoginProfile {
						p := profileA.Clone()
						p.Name = "This is User A"
						return p
					}(),
					mutPrefs: func(p *ipn.Prefs) {
						*p = *profileA.prefs().AsStruct()
						p.ProfileName = "This is User A"
					},
				}),
			},
		},
		{
			name:          "set-prefs/implicit-switch/from-new",
			initial:       &emptyProfile, // a new, empty profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// The user attempted to add a new profile but actually logged in as the same
				// node/user as profileB. When [LocalBackend.SetControlClientStatus] calls
				// [profileManager.SetPrefs] with the [persist.Persist] for profileB, we
				// implicitly switch to that profile instead of creating a duplicate for the
				// same node/user.
				//
				// TODO(nickkhyl): currently, [LocalBackend.SetControlClientStatus] uses the p
				// of the current profile, not those of the profile we switch to. This is all wrong
				// and should be fixed. But for now, we just test that the state change callback
				// is called with the new profile and p.
				p := pm.CurrentPrefs().AsStruct()
				p.Persist = profileB.prefs().Persist().AsStruct()
				p.WantRunning = true
				p.LoggedOut = false
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
			},
			wantChanges: []profileStateChange{
				// Calling [profileManager.SetPrefs] like this is effectively a profile switch
				// rather than a prefs change.
				wantProfileChange(profileState{
					LoginProfile: profileB.LoginProfile,
					mutPrefs: func(p *ipn.Prefs) {
						*p = *emptyProfile.prefs().AsStruct()
						p.Persist = profileB.prefs().Persist().AsStruct()
						p.WantRunning = true
						p.LoggedOut = false
					},
				}),
			},
		},
		{
			name:          "set-prefs/implicit-switch/from-other",
			initial:       &profileA, // profileA is the current profile
			knownProfiles: []profileState{profileA, profileB, profileC},
			action: func(pm *profileManager) {
				// Same idea, but the current profile is profileA rather than a new empty profile.
				// Note: this is all wrong. See the comment above and [profileManager.SetPrefs].
				p := pm.CurrentPrefs().AsStruct()
				p.Persist = profileB.prefs().Persist().AsStruct()
				p.WantRunning = true
				p.LoggedOut = false
				pm.SetPrefs(p.View(), ipn.NetworkProfile{})
			},
			wantChanges: []profileStateChange{
				wantProfileChange(profileState{
					LoginProfile: profileB.LoginProfile,
					mutPrefs: func(p *ipn.Prefs) {
						*p = *profileA.prefs().AsStruct()
						p.Persist = profileB.prefs().Persist().AsStruct()
						p.WantRunning = true
						p.LoggedOut = false
					},
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := new(mem.Store)
			pm, err := newProfileManagerWithGOOS(store, logger.Discard, health.NewTracker(eventbustest.NewBus(t)), "linux")
			if err != nil {
				t.Fatalf("newProfileManagerWithGOOS: %v", err)
			}
			for _, p := range tt.knownProfiles {
				pm.writePrefsToStore(p.Key, p.prefs())
				pm.knownProfiles[p.ID] = p.View()
			}
			if err := pm.writeKnownProfiles(); err != nil {
				t.Fatalf("writeKnownProfiles: %v", err)
			}

			if tt.initial != nil {
				pm.currentUserID = tt.initial.LocalUserID
				pm.currentProfile = tt.initial.View()
				pm.prefs = tt.initial.prefs()
			}

			type stateChange struct {
				Profile  *ipn.LoginProfile
				Prefs    *ipn.Prefs
				SameNode bool
			}
			wantChanges := make([]stateChange, 0, len(tt.wantChanges))
			for _, w := range tt.wantChanges {
				wantPrefs := ipn.NewPrefs()
				w.mutPrefs(wantPrefs) // apply changes to the default prefs
				wantChanges = append(wantChanges, stateChange{
					Profile:  w.LoginProfile,
					Prefs:    wantPrefs,
					SameNode: w.sameNode,
				})
			}

			gotChanges := make([]stateChange, 0, len(tt.wantChanges))
			pm.StateChangeHook = func(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
				gotChanges = append(gotChanges, stateChange{
					Profile:  profile.AsStruct(),
					Prefs:    prefs.AsStruct(),
					SameNode: sameNode,
				})
			}

			tt.action(pm)

			if diff := cmp.Diff(wantChanges, gotChanges, defaultCmpOpts...); diff != "" {
				t.Errorf("StateChange callbacks: (-want +got): %v", diff)
			}
		})
	}
}
