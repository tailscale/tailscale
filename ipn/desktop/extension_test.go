// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Both the desktop session manager and multi-user support
// are currently available only on Windows.
// This file does not need to be built for other platforms.

//go:build windows && !ts_omit_desktop_sessions

package desktop

import (
	"fmt"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

func TestUserPolicyStoreRefcount(t *testing.T) {
	setting.SetDefinitionsForTest(t,
		setting.NewDefinition(pkey.AdminConsoleVisibility, setting.UserSetting, setting.VisibilityValue),
	)
	ext := &desktopSessionsExt{
		logf: t.Logf,
	}

	uid := "S-1-5-21-1001"
	scope := setting.UserScopeOf(uid)

	store1 := source.NewTestStore(t)
	store1.SetStrings(source.TestSettingOf("AdminConsole", "hide"))
	if err := ext.ensureUserPolicyStore(uid, store1); err != nil {
		t.Fatalf("first ensureUserPolicyStore: %v", err)
	}

	policy, err := rsop.PolicyFor(scope)
	if err != nil {
		t.Fatalf("PolicyFor(%v): %v", scope, err)
	}
	snap := policy.Get()
	if got := snap.Get("AdminConsole"); got == nil {
		t.Error("expected AdminConsole in snapshot after first registration")
	}

	// Second registration for the same uid should increment refcount
	// and close the duplicate store.
	store2 := source.NewTestStore(t)
	if err := ext.ensureUserPolicyStore(uid, store2); err != nil {
		t.Fatalf("second ensureUserPolicyStore: %v", err)
	}

	// First release should decrement but keep the store alive.
	ext.releaseUserPolicyStore(uid)
	if _, ok := ext.userPolicyStores[uid]; !ok {
		t.Fatal("store removed after first release, expected refcount=1")
	}

	// Second release should clean up.
	ext.releaseUserPolicyStore(uid)
	if _, ok := ext.userPolicyStores[uid]; ok {
		t.Fatal("store still present after final release")
	}

	ext.releaseUserPolicyStore("S-1-5-21-unknown")
}

func TestUserPolicyStoreMultipleUsers(t *testing.T) {
	setting.SetDefinitionsForTest(t,
		setting.NewDefinition(pkey.AdminConsoleVisibility, setting.UserSetting, setting.VisibilityValue),
	)
	ext := &desktopSessionsExt{
		logf: t.Logf,
	}

	uidA := "S-1-5-21-1001"
	uidB := "S-1-5-21-1002"

	storeA := source.NewTestStore(t)
	storeA.SetStrings(source.TestSettingOf("AdminConsole", "hide"))

	storeB := source.NewTestStore(t)
	storeB.SetStrings(source.TestSettingOf("AdminConsole", "show"))

	if err := ext.ensureUserPolicyStore(uidA, storeA); err != nil {
		t.Fatalf("ensureUserPolicyStore(A): %v", err)
	}
	if err := ext.ensureUserPolicyStore(uidB, storeB); err != nil {
		t.Fatalf("ensureUserPolicyStore(B): %v", err)
	}

	policyA, err := rsop.PolicyFor(setting.UserScopeOf(uidA))
	if err != nil {
		t.Fatalf("PolicyFor(A): %v", err)
	}
	policyB, err := rsop.PolicyFor(setting.UserScopeOf(uidB))
	if err != nil {
		t.Fatalf("PolicyFor(B): %v", err)
	}

	if got := fmt.Sprint(policyA.Get().Get("AdminConsole")); got != "hide" {
		t.Errorf("user A AdminConsole = %v; want hide", got)
	}
	if got := fmt.Sprint(policyB.Get().Get("AdminConsole")); got != "show" {
		t.Errorf("user B AdminConsole = %v; want show", got)
	}

	ext.releaseUserPolicyStore(uidA)
	if _, ok := ext.userPolicyStores[uidB]; !ok {
		t.Fatal("user B store removed when A was released")
	}

	ext.releaseUserPolicyStore(uidB)
}
