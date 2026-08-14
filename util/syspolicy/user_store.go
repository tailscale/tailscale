// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"fmt"
	"sync"

	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

var (
	userStoreMu sync.Mutex
	userStores  map[string]*userPolicyState // keyed by Windows SID

	newUserStore func(uid string) (source.Store, error)
)

type userPolicyState struct {
	refcount int
	store    source.Store
	reg      *rsop.StoreRegistration
}

func ensureUserPolicyStore(uid string) error {
	if newUserStore == nil {
		return nil // not supported on this platform
	}

	userStoreMu.Lock()
	defer userStoreMu.Unlock()

	if ups, ok := userStores[uid]; ok {
		ups.refcount++
		return nil
	}

	store, err := newUserStore(uid)
	if err != nil {
		return fmt.Errorf("failed to create user policy store for %s: %w", uid, err)
	}
	reg, err := rsop.RegisterStore("Platform", setting.UserScopeOf(uid), store)
	if err != nil {
		if c, ok := store.(interface{ Close() error }); ok {
			c.Close()
		}
		return fmt.Errorf("failed to register user policy store for %s: %w", uid, err)
	}
	if userStores == nil {
		userStores = make(map[string]*userPolicyState)
	}
	userStores[uid] = &userPolicyState{
		refcount: 1,
		store:    store,
		reg:      reg,
	}
	return nil
}

func releaseUserPolicyStore(uid string) {
	userStoreMu.Lock()
	defer userStoreMu.Unlock()

	ups, ok := userStores[uid]
	if !ok {
		return
	}
	ups.refcount--
	if ups.refcount > 0 {
		return
	}
	ups.reg.Unregister()
	if c, ok := ups.store.(interface{ Close() error }); ok {
		c.Close()
	}
	delete(userStores, uid)
}
