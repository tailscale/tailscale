// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
)

// TestProfileManagement tests creating, loading, and switching profiles.
func TestProfileManagement(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile := ""
	wantProfiles := map[string]ipn.PrefsView{
		"": emptyPrefs,
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
			if got.Hostname() != wantProfiles[p.Name].Hostname() {
				t.Fatalf("Prefs for profile %q = %v; want %v", p, got.Pretty(), wantProfiles[p.Name].Pretty())
			}
		}
	}
	setPrefs := func(t *testing.T, loginName string) ipn.PrefsView {
		p := pm.CurrentPrefs().AsStruct()
		p.Persist = &persist.Persist{
			LoginName: loginName,
		}
		if err := pm.SetPrefs(p.View()); err != nil {
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
	wantProfiles[""] = emptyPrefs
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
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
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
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)
}

// TestProfileManagementWindows tests going into and out of Unattended mode on
// Windows.
func TestProfileManagementWindows(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile := ""
	wantProfiles := map[string]ipn.PrefsView{
		"": emptyPrefs,
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
	setPrefs := func(t *testing.T, loginName string, forceDaemon bool) ipn.PrefsView {
		p := pm.CurrentPrefs().AsStruct()
		p.ForceDaemon = forceDaemon
		p.Persist = &persist.Persist{
			LoginName: loginName,
		}
		if err := pm.SetPrefs(p.View()); err != nil {
			t.Fatal(err)
		}
		return p.View()
	}
	t.Logf("Check initial state from empty store")
	checkProfiles(t)

	{
		t.Logf("Set user1 as logged in user")
		if err := pm.SetCurrentUser("user1"); err != nil {
			t.Fatal(err)
		}
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
		wantProfiles[""] = emptyPrefs
		checkProfiles(t)

		t.Logf("Save as test profile")
		wantProfiles["test"] = setPrefs(t, "test", false)
		wantCurProfile = "test"
		checkProfiles(t)
	}

	t.Logf("Recreate profile manager from store, should reset prefs")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile = ""
	wantProfiles[""] = emptyPrefs
	checkProfiles(t)

	{
		t.Logf("Set user1 as current user")
		if err := pm.SetCurrentUser("user1"); err != nil {
			t.Fatal(err)
		}
		wantCurProfile = "test"
	}
	checkProfiles(t)
	{
		t.Logf("set unattended mode")
		wantProfiles["test"] = setPrefs(t, "test", true)
	}
	if pm.CurrentUser() != "user1" {
		t.Fatalf("CurrentUserID = %q; want %q", pm.CurrentUser(), "user1")
	}

	// Recreate the profile manager to ensure that it starts with test profile.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)
	if pm.CurrentUser() != "user1" {
		t.Fatalf("CurrentUserID = %q; want %q", pm.CurrentUser(), "user1")
	}
}
