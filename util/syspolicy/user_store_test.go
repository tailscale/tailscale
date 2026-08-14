// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"testing"

	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

func TestEnsureUserPolicyStore(t *testing.T) {
	store := source.NewTestStore(t)
	newUserStore = func(uid string) (source.Store, error) {
		return store, nil
	}
	t.Cleanup(func() {
		userStoreMu.Lock()
		userStores = nil
		userStoreMu.Unlock()
	})

	if err := ensureUserPolicyStore("user1"); err != nil {
		t.Fatal(err)
	}

	policy, err := rsop.PolicyFor(setting.UserScopeOf("user1"))
	if err != nil {
		t.Fatalf("PolicyFor: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy for user1")
	}
}

func TestEnsureUserPolicyStoreRefcount(t *testing.T) {
	store := source.NewTestStore(t)
	newUserStore = func(uid string) (source.Store, error) {
		return store, nil
	}
	t.Cleanup(func() {
		userStoreMu.Lock()
		userStores = nil
		userStoreMu.Unlock()
	})

	if err := ensureUserPolicyStore("user1"); err != nil {
		t.Fatal(err)
	}
	if err := ensureUserPolicyStore("user1"); err != nil {
		t.Fatal(err)
	}

	userStoreMu.Lock()
	rc := userStores["user1"].refcount
	userStoreMu.Unlock()
	if rc != 2 {
		t.Fatalf("refcount = %d; want 2", rc)
	}

	releaseUserPolicyStore("user1")

	userStoreMu.Lock()
	rc = userStores["user1"].refcount
	userStoreMu.Unlock()
	if rc != 1 {
		t.Fatalf("refcount after first release = %d; want 1", rc)
	}

	releaseUserPolicyStore("user1")

	userStoreMu.Lock()
	_, exists := userStores["user1"]
	userStoreMu.Unlock()
	if exists {
		t.Fatal("expected user1 store to be removed after final release")
	}
}

func TestReleaseUnknownUserIsNoop(t *testing.T) {
	releaseUserPolicyStore("nonexistent")
}
