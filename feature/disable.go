// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package feature

import (
	"runtime"
	"slices"
	"strings"
	"sync"

	"tailscale.com/envknob"
	"tailscale.com/util/set"
)

// disabledEnv is the TS_DISABLE_FEATURE environment variable: a comma
// separated list of feature names to disable in this process, even if
// they're compiled in. It's a mitigation and attack-surface-reduction
// knob, the runtime analog of the ts_omit_<name> build tags. For
// example, on a system where the tailscaled unit loads environment
// from /etc/default/tailscaled:
//
//	TS_DISABLE_FEATURE=ssh,taildrop
//
// The value is read once, at first use, which in practice is during
// package initialization; setting it later has no effect, because
// features register themselves from init.
var disabledEnv = envknob.RegisterString("TS_DISABLE_FEATURE")

// disabledByEnv is the set of normalized feature names listed in
// TS_DISABLE_FEATURE, parsed once on first use.
var disabledByEnv = sync.OnceValue(func() set.Set[string] {
	return set.SetOf(parseDisabledList(disabledEnv()))
})

// parseDisabledList splits a TS_DISABLE_FEATURE value into normalized
// feature names, skipping empty entries.
func parseDisabledList(s string) []string {
	var names []string
	for _, ent := range strings.Split(s, ",") {
		if name := normalizeFeatureName(ent); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// normalizeFeatureName canonicalizes a feature name whether it came
// from TS_DISABLE_FEATURE or from code. It trims spaces, lowercases,
// drops an optional ts_omit_ build-tag prefix, and maps underscores to
// dashes. Registered names use dashes by convention (for example
// "desktop-sessions"), but their corresponding build tags use
// underscores, so both spellings are accepted.
func normalizeFeatureName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "ts_omit_")
	return strings.ReplaceAll(s, "_", "-")
}

// Disabled reports whether the named feature has been disabled for
// this process via the TS_DISABLE_FEATURE environment variable. A
// disabled feature behaves as if it had not been linked in: [Register]
// reports false, and hooks and extensions registered by its package
// are ignored.
func Disabled(name string) bool {
	return disabledByEnv().Contains(normalizeFeatureName(name))
}

// EnvDisabled returns the sorted feature names listed in the
// TS_DISABLE_FEATURE environment variable, whether or not they name
// features that this build contains. It is for diagnostics, such as
// the debug-features LocalAPI endpoint.
func EnvDisabled() []string {
	names := disabledByEnv().Slice()
	slices.Sort(names)
	return names
}

// featurePkgPrefix is the import path prefix of the feature package
// tree. The name of a package under it is the first path element after
// the prefix, so sub-packages of a feature (such as
// feature/captiveportal/netcheckhook) count as their parent feature.
const featurePkgPrefix = "tailscale.com/feature/"

// mechanismPkgPrefix is the prefix of symbol names belonging to the
// registration machinery itself (this package), which the stack walk
// in callerFeatureName steps over to find the registering feature. It
// matches both plain functions (tailscale.com/feature.callerFeatureName)
// and methods (tailscale.com/feature.(*Hook[...]).Set).
const mechanismPkgPrefix = "tailscale.com/feature."

// callerFeatureDisabled reports whether the feature package calling
// into this package has been disabled via TS_DISABLE_FEATURE. It backs
// the silent skip in [Hook.Set] and [Hooks.Add] so that a feature
// package which registers hooks without first consulting [Register]
// still gets disabled. If the caller is not a feature package, it
// reports false.
func callerFeatureDisabled() bool {
	name, ok := callerFeatureName()
	return ok && Disabled(name)
}

// callerFeatureName walks up the call stack, starting just above this
// package's own frames, and returns the name of the first calling
// package under tailscale.com/feature/. The second result is false if
// no calling feature package is found, which means the caller is
// ordinary code and its registration is always wanted.
//
// Frames are matched by symbol name prefix rather than by parsing out
// package paths, because the symbol name of a Hook.Set frame includes
// its type parameters, which themselves contain import paths.
func callerFeatureName() (string, bool) {
	var pcs [16]uintptr
	n := runtime.Callers(1, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		fn := frame.Function
		switch {
		case fn == "":
			return "", false
		case strings.HasPrefix(fn, mechanismPkgPrefix):
			// A frame of the registration machinery; look above it.
		case strings.HasPrefix(fn, featurePkgPrefix):
			rest := strings.TrimPrefix(fn, featurePkgPrefix)
			if i := strings.IndexAny(rest, "/."); i >= 0 {
				rest = rest[:i]
			}
			return rest, true
		default:
			// A frame outside the feature tree; the search is over.
			return "", false
		}
		if !more {
			return "", false
		}
	}
}
