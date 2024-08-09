// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/winutil/gp"
)

const (
	softwareKeyName  = "Software"
	tsPoliciesSubkey = `Policies\Tailscale`
	tsIPNSubkey      = "Tailscale IPN" // the legacy key we need to fallback to
)

var (
	// [PlatformPolicyStore] implements [Store].
	_ Store = (*PlatformPolicyStore)(nil)
)

// PlatformPolicyStore implements [Store] by providing read access to the Registry-based
// Tailscale policies, such as those configured via Group Policy or MDM. It is
// recommended to lock it when reading multiple policy values in a row. It also
// allows subscribing to notifications when there's a policy change.
type PlatformPolicyStore struct {
	scope gp.Scope // [gp.MachinePolicy] or [gp.UserPolicy]

	// The softwareKey can be HKLM\Software, HKCU\Software, or
	// HKU\{SID}\Software. Anything below the Software subkey, including
	// Software\Policies, may not yet exist or could be deleted throughout the
	// [PlatformPolicyStore]'s lifespan, invalidating the handle. We also prefer
	// to always use a real registry key (rather than a predefined HKLM or HKCU)
	// to simplify bookkeeping (predefined keys should never be closed).
	// Finally, this will allow us to watch for any registry changes directly
	// should we need this in the future in addition to gp.ChangeWatcher.
	softwareKey registry.Key
	watcher     *gp.ChangeWatcher

	done chan struct{} // done is closed when Close call completes

	// The policyLock can be locked by the caller when reading multiple policy settings
	// to prevent the Group Policy Client service from modifying policies while
	// they are being read.
	//
	// When both policyLock and mu need to be taken, mu must be taken before policyLock.
	policyLock *gp.PolicyLock

	mu       sync.RWMutex
	tsKeys   []registry.Key        // or nil if the [PlatformPolicyStore] hasn't been locked.
	cbs      set.HandleSet[func()] // policy change callbacks
	lockCnt  int
	locked   sync.WaitGroup
	closing  bool
	readable bool
}

type registryValueGetter[T any] func(key registry.Key, name setting.Key) (T, error)

// NewMachinePlatformPolicyStore returns a new [PlatformPolicyStore] for the machine.
func NewMachinePlatformPolicyStore() (*PlatformPolicyStore, error) {
	softwareKey, err := registry.OpenKey(registry.LOCAL_MACHINE, softwareKeyName, windows.KEY_READ)
	if err != nil {
		return nil, fmt.Errorf("failed to open the %s key: %w", softwareKeyName, err)
	}
	return newPlatformPolicyStore(gp.MachinePolicy, softwareKey, 0)
}

// NewUserPlatformPolicyStore returns a new [PlatformPolicyStore] for the user specified by its token.
// User's profile must be loaded, and the token handle must have [windows.TOKEN_QUERY]
// access. The caller retains ownership of the token.
func NewUserPlatformPolicyStore(token windows.Token) (*PlatformPolicyStore, error) {
	var err error
	var softwareKey registry.Key
	if token != 0 {
		var user *windows.Tokenuser
		if user, err = token.GetTokenUser(); err != nil {
			return nil, fmt.Errorf("failed to get token user: %w", err)
		}
		userSid := user.User.Sid
		softwareKey, err = registry.OpenKey(registry.USERS, userSid.String()+`\`+softwareKeyName, windows.KEY_READ)
	} else {
		softwareKey, err = registry.OpenKey(registry.CURRENT_USER, softwareKeyName, windows.KEY_READ)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open the %s key: %w", softwareKeyName, err)
	}
	return newPlatformPolicyStore(gp.UserPolicy, softwareKey, token)
}

func newPlatformPolicyStore(scope gp.Scope, softwareKey registry.Key, token windows.Token) (_ *PlatformPolicyStore, err error) {
	store := &PlatformPolicyStore{
		scope:       scope,
		softwareKey: softwareKey,
		done:        make(chan struct{}),
		readable:    true,
	}
	defer func() {
		if err != nil {
			store.Close()
		}
	}()

	switch scope {
	case gp.MachinePolicy:
		store.policyLock = gp.NewMachinePolicyLock()
	case gp.UserPolicy:
		if store.policyLock, err = gp.NewUserPolicyLock(token); err != nil {
			return nil, fmt.Errorf("failed to create a user policy lock: %w", err)
		}
	default:
		panic("unreachable")
	}

	return store, nil
}

// Lock locks the policy store, preventing the system from modifying the policies
// while they are being read. It is a read lock that may be acquired by multiple goroutines.
// Each Lock call must be balanced by exactly one Unlock call.
func (ps *PlatformPolicyStore) Lock() (err error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.closing {
		return ErrStoreClosed
	}

	ps.lockCnt += 1
	if ps.lockCnt != 1 {
		return nil
	}
	defer func() {
		if err != nil {
			ps.lockCnt -= 1
		}
	}()

	// Ensure ps remains open while the lock is held.
	ps.locked.Add(1)
	defer func() {
		if err != nil {
			ps.locked.Done()
		}
	}()

	// Acquire the GP lock to prevent the system from modifying policy settings
	// while they are being read.
	if err := ps.policyLock.Lock(); err != nil {
		if errors.Is(err, gp.ErrInvalidLockState) {
			return ErrStoreClosed
		}
		return err
	}
	defer func() {
		if err != nil {
			ps.policyLock.Unlock()
		}
	}()

	// Keep the Tailscale's registry keys open for the duration of the lock.
	keyNames := tailscaleKeyNamesFor(ps.scope)
	ps.tsKeys = make([]registry.Key, 0, len(keyNames))
	for _, keyName := range keyNames {
		var tsKey registry.Key
		tsKey, err = registry.OpenKey(ps.softwareKey, keyName, windows.KEY_READ)
		if err != nil {
			if err == registry.ErrNotExist {
				continue
			}
			return err
		}
		ps.tsKeys = append(ps.tsKeys, tsKey)
	}

	return nil
}

// Unlock decrements the lock counter and unlocks the policy store once the counter reaches 0.
// It panics if ps is not locked on entry to Unlock.
func (ps *PlatformPolicyStore) Unlock() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.lockCnt -= 1
	if ps.lockCnt < 0 {
		panic("negative lockCnt")
	} else if ps.lockCnt != 0 {
		return
	}

	for _, key := range ps.tsKeys {
		key.Close()
	}
	ps.tsKeys = nil
	ps.policyLock.Unlock()
	ps.locked.Done()
}

// RegisterChangeCallback adds a function that will be called whenever there's a policy change.
// It returns a function that needs to be called to unregister the specified callback or an error.
// The error is [ErrStoreClosed] if ps has already been closed.
func (ps *PlatformPolicyStore) RegisterChangeCallback(cb func()) (unregister func(), err error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.closing {
		return nil, ErrStoreClosed
	}

	handle := ps.cbs.Add(cb)
	if len(ps.cbs) == 1 {
		if ps.watcher, err = gp.NewChangeWatcher(ps.scope, ps.onChange); err != nil {
			return nil, err
		}
	}

	return func() {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		delete(ps.cbs, handle)
		if len(ps.cbs) == 0 {
			if ps.watcher != nil {
				ps.watcher.Close()
				ps.watcher = nil
			}
		}
	}, nil
}

func (ps *PlatformPolicyStore) onChange() {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if ps.closing {
		return
	}
	for _, callback := range ps.cbs {
		go callback()
	}
}

// ReadString retrieves a string policy with the specified name.
// It returns [ErrNotConfigured] if the policy setting does not exist.
func (ps *PlatformPolicyStore) ReadString(name setting.Key) (val string, err error) {
	return getPolicyValue(ps, canonicalizeValueName(name),
		func(key registry.Key, name setting.Key) (string, error) {
			val, _, err := key.GetStringValue(string(name))
			return val, err
		})
}

// ReadUInt64 retrieves an integer policy with the specified name.
// It returns [ErrNotConfigured] if the policy setting does not exist.
func (ps *PlatformPolicyStore) ReadUInt64(name setting.Key) (uint64, error) {
	return getPolicyValue(ps, canonicalizeValueName(name),
		func(key registry.Key, name setting.Key) (uint64, error) {
			val, _, err := key.GetIntegerValue(string(name))
			return val, err
		})
}

// ReadBoolean retrieves a boolean policy with the specified name.
// It returns [ErrNotConfigured] if the policy setting does not exist.
func (ps *PlatformPolicyStore) ReadBoolean(name setting.Key) (bool, error) {
	return getPolicyValue(ps, canonicalizeValueName(name),
		func(key registry.Key, name setting.Key) (bool, error) {
			val, _, err := key.GetIntegerValue(string(name))
			if err != nil {
				return false, err
			}
			return val != 0, nil
		})
}

// ReadString retrieves a multi-string policy with the specified name.
// It returns [ErrNotConfigured] if the policy setting does not exist.
func (ps *PlatformPolicyStore) ReadStringArray(name setting.Key) ([]string, error) {
	return getPolicyValue(ps, name,
		func(key registry.Key, name setting.Key) ([]string, error) {
			val, _, err := key.GetStringsValue(string(canonicalizeValueName(name)))
			if err != registry.ErrNotExist {
				return val, err
			}

			// The idiomatic way to store multiple string values in Group Policy
			// and MDM for Windows is to have multiple REG_SZ (or REG_EXPAND_SZ)
			// values under a subkey rather than in a single REG_MULTI_SZ value.
			//
			// See the Group Policy: Registry Extension Encoding specification,
			// and specifically the ListElement and ListBox types.
			// https://web.archive.org/web/20240721033657/https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GPREG/%5BMS-GPREG%5D.pdf
			valKey, err := registry.OpenKey(key, string(canonicalizeKeyName(name)), windows.KEY_READ)
			if err != nil {
				return nil, err
			}
			valNames, err := valKey.ReadValueNames(0)
			if err != nil {
				return nil, err
			}
			val = make([]string, 0, len(valNames))
			for _, name := range valNames {
				switch item, _, err := valKey.GetStringValue(name); {
				case err == registry.ErrNotExist:
					continue
				case err != nil:
					return nil, err
				default:
					val = append(val, item)
				}
			}
			return val, nil
		})
}

func canonicalizeKeyName(name setting.Key) setting.Key {
	return setting.Key(strings.ReplaceAll(string(name), setting.KeyPathSeparator, `\`))
}

func canonicalizeValueName(name setting.Key) setting.Key {
	return setting.Key(strings.ReplaceAll(string(name), setting.KeyPathSeparator, `_`))
}

func getPolicyValue[T any](ps *PlatformPolicyStore, name setting.Key, getter registryValueGetter[T]) (T, error) {
	var zero T

	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if !ps.readable {
		return zero, setting.ErrNotConfigured
	}

	if ps.tsKeys != nil {
		// A non-nil tsKeys indicates that ps has been locked.
		// It may be empty if Tailscale policy keys do not exist.
		for _, tsKey := range ps.tsKeys {
			val, err := getter(tsKey, name)
			if err == nil || err != registry.ErrNotExist {
				return val, err
			}
		}
		return zero, setting.ErrNotConfigured
	}

	// The ps has not been locked, so we don't have any pre-opened keys.
	for _, tsKeyName := range tailscaleKeyNamesFor(ps.scope) {
		var tsKey registry.Key
		tsKey, err := registry.OpenKey(ps.softwareKey, tsKeyName, windows.KEY_READ)
		if err != nil {
			if err == registry.ErrNotExist {
				continue
			}
			return zero, err
		}
		defer tsKey.Close()

		val, err := getter(tsKey, name)
		if err == nil || err != registry.ErrNotExist {
			return val, err
		}
	}

	return zero, setting.ErrNotConfigured
}

// Close closes the policy store and releases any associated resources.
// It cancels pending locks and prevents any new lock attempts,
// but waits for existing locks to be released.
func (ps *PlatformPolicyStore) Close() error {
	// Request to close the Group Policy read lock.
	// Existing held locks will remain valid, but any new or pending locks
	// will fail. In certain scenarios, the corresponding write lock may be held
	// by the Group Policy service for extended periods (minutes rather than
	// seconds or milliseconds). In such cases, we prefer not to wait that long
	// if the ps is being closed anyway.
	if ps.policyLock != nil {
		ps.policyLock.Close()
	}

	// Signal to the external code that ps should no longer be used.
	close(ps.done)

	// Mark ps as closing to fast-fail any new lock attempts.
	// Callers that have already locked it can finish their reading.
	ps.mu.Lock()
	if ps.closing {
		ps.mu.Unlock()
		return nil
	}
	ps.closing = true
	if ps.watcher != nil {
		ps.watcher.Close()
		ps.watcher = nil
	}
	ps.mu.Unlock()

	// Wait for any outstanding locks to be released.
	ps.locked.Wait()

	// Deny any further read attempts and release remaining resources.
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.cbs = nil
	ps.policyLock = nil
	ps.readable = false
	if ps.softwareKey != 0 {
		ps.softwareKey.Close()
		ps.softwareKey = 0
	}
	return nil
}

// Done returns a channel that is closed when the Close method is called.
func (ps *PlatformPolicyStore) Done() <-chan struct{} {
	return ps.done
}

func tailscaleKeyNamesFor(scope gp.Scope) []string {
	switch scope {
	case gp.MachinePolicy:
		// If a computer-side policy value does not exist under Software\Policies\Tailscale,
		// we need to fallback and use the legacy Software\Tailscale IPN key.
		return []string{tsPoliciesSubkey, tsIPNSubkey}
	case gp.UserPolicy:
		// However, we've never used the legacy key with user-side policies,
		// and we should never do so. Unlike HKLM\Software\Tailscale IPN,
		// its HKCU counterpart is user-writable.
		return []string{tsPoliciesSubkey}
	default:
		panic("unreachable")
	}
}
