// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package rsop facilitates [source.Store] registration via [RegisterStore]
// and provides access to the effective policy merged from all registered sources
// via [PolicyFor].
package rsop

import (
	"errors"
	"fmt"
	"slices"

	"tailscale.com/syncs"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

var (
	policyMu          syncs.Mutex      // protects [policySources] and [effectivePolicies]
	policySources     []*source.Source // all registered policy sources
	effectivePolicies []*Policy        // all active (non-closed) effective policies returned by [PolicyFor]

	// effectivePolicyLRU is an LRU cache of [Policy] by [setting.Scope].
	// Although there could be multiple [setting.PolicyScope] instances with the same [setting.Scope],
	// such as two user scopes for different users, there is only one [setting.DeviceScope], only one
	// [setting.CurrentProfileScope], and in most cases, only one active user scope.
	// Therefore, cache misses that require falling back to [effectivePolicies] are extremely rare.
	// It's a fixed-size array of atomic values and can be accessed without [policyMu] held.
	effectivePolicyLRU [setting.NumScopes]syncs.AtomicValue[*Policy]
)

// PolicyFor returns the [Policy] for the specified scope,
// creating it from the registered [source.Store]s if it doesn't already exist.
func PolicyFor(scope setting.PolicyScope) (*Policy, error) {
	if err := internal.Init.Do(); err != nil {
		return nil, err
	}
	policy := effectivePolicyLRU[scope.Kind()].Load()
	if policy != nil && policy.Scope() == scope && policy.IsValid() {
		return policy, nil
	}
	return policyForSlow(scope)
}

func policyForSlow(scope setting.PolicyScope) (policy *Policy, err error) {
	defer func() {
		// Always update the LRU cache on exit if we found (or created)
		// a policy for the specified scope.
		if policy != nil {
			effectivePolicyLRU[scope.Kind()].Store(policy)
		}
	}()

	policyMu.Lock()
	defer policyMu.Unlock()
	if policy, ok := findPolicyByScopeLocked(scope); ok {
		return policy, nil
	}

	// If there is no existing effective policy for the specified scope,
	// we need to create one using the policy sources registered for that scope.
	sources := slicesx.Filter(nil, policySources, func(source *source.Source) bool {
		return source.Scope().Contains(scope)
	})
	policy, err = newPolicy(scope, sources...)
	if err != nil {
		return nil, err
	}
	effectivePolicies = append(effectivePolicies, policy)
	return policy, nil
}

// findPolicyByScopeLocked returns a policy with the specified scope and true if
// one exists in the [effectivePolicies] list, otherwise it returns nil, false.
// [policyMu] must be held.
func findPolicyByScopeLocked(target setting.PolicyScope) (policy *Policy, ok bool) {
	for _, policy := range effectivePolicies {
		if policy.Scope() == target && policy.IsValid() {
			return policy, true
		}
	}
	return nil, false
}

// deletePolicy deletes the specified effective policy from [effectivePolicies]
// and [effectivePolicyLRU].
func deletePolicy(policy *Policy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	if i := slices.Index(effectivePolicies, policy); i != -1 {
		effectivePolicies = slices.Delete(effectivePolicies, i, i+1)
	}
	effectivePolicyLRU[policy.Scope().Kind()].CompareAndSwap(policy, nil)
}

// registerSource registers the specified [source.Source] to be used by the package.
// It updates existing [Policy]s returned by [PolicyFor] to use this source if
// they are within the source's [setting.PolicyScope].
func registerSource(source *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	if slices.Contains(policySources, source) {
		// already registered
		return nil
	}
	policySources = append(policySources, source)
	return forEachEffectivePolicyLocked(func(policy *Policy) error {
		if !source.Scope().Contains(policy.Scope()) {
			// Policy settings in the specified source do not apply
			// to the scope of this effective policy.
			// For example, a user policy source is being registered
			// while the effective policy is for the device (or another user).
			return nil
		}
		return policy.addSource(source)
	})
}

// replaceSource is like [unregisterSource](old) followed by [registerSource](new),
// but performed atomically: the effective policy will contain settings
// either from the old source or the new source, never both and never neither.
func replaceSource(old, new *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	oldIndex := slices.Index(policySources, old)
	if oldIndex == -1 {
		return fmt.Errorf("the source is not registered: %v", old)
	}
	policySources[oldIndex] = new
	return forEachEffectivePolicyLocked(func(policy *Policy) error {
		if !old.Scope().Contains(policy.Scope()) || !new.Scope().Contains(policy.Scope()) {
			return nil
		}
		return policy.replaceSource(old, new)
	})
}

// unregisterSource unregisters the specified [source.Source],
// so that it won't be used by any new or existing [Policy].
func unregisterSource(source *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	index := slices.Index(policySources, source)
	if index == -1 {
		return nil
	}
	policySources = slices.Delete(policySources, index, index+1)
	return forEachEffectivePolicyLocked(func(policy *Policy) error {
		if !source.Scope().Contains(policy.Scope()) {
			return nil
		}
		return policy.removeSource(source)
	})
}

// forEachEffectivePolicyLocked calls fn for every non-closed [Policy] in [effectivePolicies].
// It accumulates the returned errors and returns an error that wraps all errors returned by fn.
// The [policyMu] mutex must be held while this function is executed.
func forEachEffectivePolicyLocked(fn func(p *Policy) error) error {
	var errs []error
	for _, policy := range effectivePolicies {
		if policy.IsValid() {
			err := fn(policy)
			if err != nil && !errors.Is(err, ErrPolicyClosed) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
