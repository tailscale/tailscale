// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"fmt"
	"slices"
	"strings"
)

// isDangerousEnvVar reports whether the given environment variable name
// is unconditionally prohibited from being forwarded, regardless of
// acceptEnv policy. This prevents privilege escalation via dynamic
// linker environment variables (e.g. LD_PRELOAD, LD_LIBRARY_PATH,
// DYLD_INSERT_LIBRARIES) even when a wildcard acceptEnv pattern like
// "*" is configured.
func isDangerousEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_")
}

// allowedEnvKeysEnv is the name of the environment variable used to pass the
// comma-separated list of client-forwarded environment variable names from the
// parent (tailscaled) to the incubator child. The names are passed via the
// environment rather than on the argv so they never appear in the child's
// /proc/<pid>/cmdline (visible to other local users) or in process logs. The
// incubator strips this variable from the environment before handing off to the
// user's process (see stripAllowedEnvKeys).
//
// Because the child reads this back out of its own environment (which also
// contains the client-forwarded variables) a client that could forward a
// variable of this exact name, or a key containing the "," separator, could
// spoof or widen the reconstructed "su -w" allowlist. filterEnv rejects both,
// so this name is reserved and never client-controllable.
const allowedEnvKeysEnv = "TS_SSH_ALLOWED_ENV_KEYS"

// reservedEnvKey reports whether name must never be accepted from the client as
// a forwarded environment variable, independent of the acceptEnv policy. A key
// is reserved if it collides with the allowedEnvKeysEnv bookkeeping variable or
// if it contains the "," character used to separate key names within that
// variable (which would let a client inject additional entries into the
// incubator's "su -w" allowlist). An empty key name is likewise rejected as
// malformed.
func reservedEnvKey(name string) bool {
	return name == "" || name == allowedEnvKeysEnv || strings.Contains(name, ",")
}

// stripAllowedEnvKeys removes every occurrence of the allowedEnvKeysEnv
// bookkeeping variable from environ and returns the remaining environment along
// with the key names that variable carried (its comma-separated value, empty
// entries skipped). It filters environ in place (via slices.DeleteFunc), so the
// caller must pass a slice it owns, such as a fresh os.Environ(). It is the
// child-side counterpart to forwardedEnvAndKeys and is shared by the
// platform-specific forwardedEnviron implementations so the stripping and
// allowlist reconstruction behave identically everywhere.
func stripAllowedEnvKeys(environ []string) (env, keys []string) {
	env = slices.DeleteFunc(environ, func(kv string) bool {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k != allowedEnvKeysEnv {
			return false
		}
		for _, ek := range strings.Split(v, ",") {
			if ek != "" {
				keys = append(keys, ek)
			}
		}
		return true
	})
	return env, keys
}

// filterEnv filters a passed in environ string slice (a slice with strings
// representing environment variables in the form "key=value") based on
// the supplied slice of acceptEnv values.
//
// acceptEnv is a slice of environment variable names that are allowlisted
// for the SSH rule in the policy file.
//
// acceptEnv values may contain * and ? wildcard characters which match against
// zero or one or more characters and a single character respectively.
//
// Certain dangerous environment variables (such as those controlling the
// dynamic linker) are always rejected regardless of the acceptEnv policy.
// See isDangerousEnvVar.
func filterEnv(acceptEnv []string, environ []string) ([]string, error) {
	var acceptedPairs []string

	// Quick return if we have an empty list.
	if acceptEnv == nil || len(acceptEnv) == 0 {
		return acceptedPairs, nil
	}

	for _, envPair := range environ {
		variableName, _, ok := strings.Cut(envPair, "=")
		if !ok {
			return nil, fmt.Errorf(`invalid environment variable: %q. Variables must be in "KEY=VALUE" format`, envPair)
		}

		// Always reject dangerous environment variables that could
		// enable privilege escalation, regardless of acceptEnv policy.
		if isDangerousEnvVar(variableName) {
			continue
		}

		// Always reject names reserved for our own parent->child bookkeeping
		// (see reservedEnvKey), regardless of acceptEnv policy, so a client
		// cannot spoof or widen the incubator's "su -w" allowlist.
		if reservedEnvKey(variableName) {
			continue
		}

		// Short circuit if we have a direct match between the environment
		// variable and an AcceptEnv value.
		if slices.Contains(acceptEnv, variableName) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}

		// Otherwise check if we have a wildcard pattern that matches.
		if matchAcceptEnv(acceptEnv, variableName) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}
	}

	return acceptedPairs, nil
}

// matchAcceptEnv is a convenience function that wraps calling matchAcceptEnvPattern
// with every value in acceptEnv for a given env that is being matched against.
func matchAcceptEnv(acceptEnv []string, env string) bool {
	for _, pattern := range acceptEnv {
		if matchAcceptEnvPattern(pattern, env) {
			return true
		}
	}

	return false
}

// matchAcceptEnvPattern returns true if the pattern matches against the target string.
// Patterns may include * and ? wildcard characters which match against zero or one or
// more characters and a single character respectively.
func matchAcceptEnvPattern(pattern string, target string) bool {
	patternIdx := 0
	targetIdx := 0

	for {
		// If we are at the end of the pattern we can only have a match if we
		// are also at the end of the target.
		if patternIdx >= len(pattern) {
			return targetIdx >= len(target)
		}

		if pattern[patternIdx] == '*' {
			// Optimization to skip through any repeated asterisks as they
			// have the same net effect on our search.
			for patternIdx < len(pattern) {
				if pattern[patternIdx] != '*' {
					break
				}

				patternIdx++
			}

			// We are at the end of the pattern after matching the asterisk,
			// implying a match.
			if patternIdx >= len(pattern) {
				return true
			}

			// Search through the target sequentially for the next character
			// from the pattern string, recursing into matchAcceptEnvPattern
			// to try and find a match.
			for ; targetIdx < len(target); targetIdx++ {
				if matchAcceptEnvPattern(pattern[patternIdx:], target[targetIdx:]) {
					return true
				}
			}

			// No match after searching through the entire target.
			return false
		}

		if targetIdx >= len(target) {
			return false
		}

		if pattern[patternIdx] != '?' && pattern[patternIdx] != target[targetIdx] {
			return false
		}

		patternIdx++
		targetIdx++
	}
}
