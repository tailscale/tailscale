// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"os/user"
	"strconv"
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
	"tailscale.com/util/must"
)

func TestProfileCurrentUserSwitch(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	newProfile := func(t *testing.T, loginName string) ipn.PrefsView {
		id++
		t.Helper()
		pm.NewProfile()
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
	pm.DeleteProfile(cp.ID)
	if pm.currentProfile == nil {
		t.Fatal("currentProfile is nil")
	} else if pm.currentProfile.ID != "" {
		t.Fatalf("currentProfile.ID = %q, want empty", pm.currentProfile.ID)
	}
	if !pm.CurrentPrefs().Equals(defaultPrefs) {
		t.Fatalf("CurrentPrefs() = %v, want emptyPrefs", pm.CurrentPrefs().Pretty())
	}

	pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
	if err != nil {
		t.Fatal(err)
	}
	pm.SetCurrentUserID("user1")
	if pm.currentProfile == nil {
		t.Fatal("currentProfile is nil")
	} else if pm.currentProfile.ID != "" {
		t.Fatalf("currentProfile.ID = %q, want empty", pm.currentProfile.ID)
	}
	if !pm.CurrentPrefs().Equals(defaultPrefs) {
		t.Fatalf("CurrentPrefs() = %v, want emptyPrefs", pm.CurrentPrefs().Pretty())
	}
}

func TestProfileList(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	newProfile := func(t *testing.T, loginName string) ipn.PrefsView {
		id++
		t.Helper()
		pm.NewProfile()
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
			if got[i].Name != w {
				t.Errorf("got profile %d name %q, want %q", i, got[i].Name, w)
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
	if lp := pm.findProfileByKey(carol.Key); lp != nil {
		t.Fatalf("found profile for user2 in user1's profile list")
	}
	if lp := pm.findProfileByName(carol.Name); lp != nil {
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
		pm.NewProfile()
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
			pm, err := newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tc.steps {
				s.fn(pm, s.p)
			}
			profs := pm.Profiles()
			var got []*persist.Persist
			for _, p := range profs {
				prefs, err := pm.loadSavedPrefs(p.Key)
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

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
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
		t.Logf("\tCurrentProfile = %q", prof)
		if prof.Name != wantCurProfile {
			t.Fatalf("CurrentProfile = %q; want %q", prof, wantCurProfile)
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
			got, err := pm.loadSavedPrefs(p.Key)
			if err != nil {
				t.Fatal(err)
			}
			// Use Hostname as a proxy for all prefs.
			if !got.Equals(wantProfiles[p.Name]) {
				t.Fatalf("Prefs for profile %q =\n got=%+v\nwant=%v", p, got.Pretty(), wantProfiles[p.Name].Pretty())
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
	pm.NewProfile()
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
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	t.Logf("Delete default profile")
	if err := pm.DeleteProfile(pm.findProfileByName("user@1.example.com").ID); err != nil {
		t.Fatal(err)
	}
	delete(wantProfiles, "user@1.example.com")
	checkProfiles(t)

	t.Logf("Recreate profile manager from store after deleting default profile")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	t.Logf("Create new profile - 2")
	pm.NewProfile()
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
		pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "linux")
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

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "windows")
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
		t.Logf("\tCurrentProfile = %q", prof)
		if prof.Name != wantCurProfile {
			t.Fatalf("CurrentProfile = %q; want %q", prof, wantCurProfile)
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
		pm.NewProfile()
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
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "windows")
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
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, new(health.Tracker), "windows")
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
