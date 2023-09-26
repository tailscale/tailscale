// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policy contains higher-level abstractions for accessing Windows enterprise policies.
package policy

import (
	"time"

	"tailscale.com/util/winutil"
)

// PreferenceOptionPolicy is a policy that governs whether a boolean variable
// is forcibly assigned an administrator-defined value, or allowed to receive
// a user-defined value.
type PreferenceOptionPolicy int

const (
	showChoiceByPolicy PreferenceOptionPolicy = iota
	neverByPolicy
	alwaysByPolicy
)

// Show returns if the UI option that controls the choice administered by this
// policy should be shown. Currently this is true if and only if the policy is
// showChoiceByPolicy.
func (p PreferenceOptionPolicy) Show() bool {
	return p == showChoiceByPolicy
}

// ShouldEnable checks if the choice administered by this policy should be
// enabled. If the administrator has chosen a setting, the administrator's
// setting is returned, otherwise userChoice is returned.
func (p PreferenceOptionPolicy) ShouldEnable(userChoice bool) bool {
	switch p {
	case neverByPolicy:
		return false
	case alwaysByPolicy:
		return true
	default:
		return userChoice
	}
}

// GetPreferenceOptionPolicy loads a policy from the registry that can be
// managed by an enterprise policy management system and allows administrative
// overrides of users' choices in a way that we do not want tailcontrol to have
// the authority to set. It describes user-decides/always/never options, where
// "always" and "never" remove the user's ability to make a selection. If not
// present or set to a different value, "user-decides" is the default.
func GetPreferenceOptionPolicy(name string) PreferenceOptionPolicy {
	opt, err := winutil.GetPolicyString(name)
	if opt == "" || err != nil {
		return showChoiceByPolicy
	}
	switch opt {
	case "always":
		return alwaysByPolicy
	case "never":
		return neverByPolicy
	default:
		return showChoiceByPolicy
	}
}

// VisibilityPolicy is a policy that controls whether or not a particular
// component of a user interface is to be shown.
type VisibilityPolicy byte

const (
	visibleByPolicy VisibilityPolicy = 'v'
	hiddenByPolicy  VisibilityPolicy = 'h'
)

// Show reports whether the UI option administered by this policy should be shown.
// Currently this is true if and only if the policy is visibleByPolicy.
func (p VisibilityPolicy) Show() bool {
	return p == visibleByPolicy
}

// GetVisibilityPolicy loads a policy from the registry that can be managed
// by an enterprise policy management system and describes show/hide decisions
// for UI elements. The registry value should be a string set to "show" (return
// true) or "hide" (return true). If not present or set to a different value,
// "show" (return false) is the default.
func GetVisibilityPolicy(name string) VisibilityPolicy {
	opt, err := winutil.GetPolicyString(name)
	if opt == "" || err != nil {
		return visibleByPolicy
	}
	switch opt {
	case "hide":
		return hiddenByPolicy
	default:
		return visibleByPolicy
	}
}

// GetDurationPolicy loads a policy from the registry that can be managed
// by an enterprise policy management system and describes a duration for some
// action. The registry value should be a string that time.ParseDuration
// understands. If the registry value is "" or can not be processed,
// defaultValue is returned instead.
func GetDurationPolicy(name string, defaultValue time.Duration) time.Duration {
	opt, err := winutil.GetPolicyString(name)
	if opt == "" || err != nil {
		return defaultValue
	}
	v, err := time.ParseDuration(opt)
	if err != nil || v < 0 {
		return defaultValue
	}
	return v
}

// SelectControlURL returns the ControlURL to use based on a value in
// the registry (LoginURL) and the one on disk (in the GUI's
// prefs.conf). If both are empty, it returns a default value. (It
// always return a non-empty value)
//
// See https://github.com/tailscale/tailscale/issues/2798 for some background.
func SelectControlURL(reg, disk string) string {
	const def = "https://controlplane.tailscale.com"

	// Prior to Dec 2020's commit 739b02e6, the installer
	// wrote a LoginURL value of https://login.tailscale.com to the registry.
	const oldRegDef = "https://login.tailscale.com"

	// If they have an explicit value in the registry, use it,
	// unless it's an old default value from an old installer.
	// Then we have to see which is better.
	if reg != "" {
		if reg != oldRegDef {
			// Something explicit in the registry that we didn't
			// set ourselves by the installer.
			return reg
		}
		if disk == "" {
			// Something in the registry is better than nothing on disk.
			return reg
		}
		if disk != def && disk != oldRegDef {
			// The value in the registry is the old
			// default (login.tailscale.com) but the value
			// on disk is neither our old nor new default
			// value, so it must be some custom thing that
			// the user cares about. Prefer the disk value.
			return disk
		}
	}
	if disk != "" {
		return disk
	}
	return def
}
