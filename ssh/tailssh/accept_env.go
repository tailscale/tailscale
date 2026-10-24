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
// DYLD_INSERT_LIBRARIES) or leaking of secrets (e.g. GOTRACEBACK)
// even when a wildcard acceptEnv pattern like "*" is configured.
//
// The denylist also covers other root su/login environment exposure
// classes: glibc module/file lookups and tunables parsing
// (GCONV_PATH, LOCPATH, NLSPATH, GLIBC_TUNABLES; CVE-2023-4911 class —
// glibc parses tunables in root su/login environments with
// AT_SECURE=0) that can load attacker-controlled files or code into
// privileged processes, and resolver configuration (HOSTALIASES,
// RES_OPTIONS) that can redirect privileged hostname lookups.
func isDangerousEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") ||
		upper == "GOTRACEBACK" || upper == "GCONV_PATH" || upper == "LOCPATH" ||
		upper == "NLSPATH" || upper == "HOSTALIASES" || upper == "RES_OPTIONS" ||
		upper == "GLIBC_TUNABLES"
}

// forbiddenEnvKey reports whether name must never be accepted from the client as a
// forwarded environment variable, independent of the acceptEnv policy. Names are
// restricted to a known-safe charset so they cannot corrupt the "su -w" allowlist
// built from them, truncate on exec, or confuse downstream consumers of the user's
// environment.
func forbiddenEnvKey(name string) bool {
	for _, r := range name {
		if r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return true
		}
	}
	return name == ""
}

// maxAcceptEnvNameLen caps the length of an accepted environment variable
// name. Names are short (LOGIN_NAME_MAX is 256 on Linux); a longer "name"
// is bogus and would only serve to tie up the pattern matcher or bloat the
// child's "su -w" allowlist.
const maxAcceptEnvNameLen = 256

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

		// Bound the matcher and allowlist input: names are short
		// (LOGIN_NAME_MAX), so a longer one is bogus. Reject before any
		// wildcard matching runs.
		if len(variableName) > maxAcceptEnvNameLen {
			continue
		}

		// Reject NUL bytes: envp entries are NUL-terminated, so a NUL would silently truncate on exec
		if strings.Contains(envPair, "\x00") {
			continue
		}

		// Always reject dangerous environment variables that could
		// enable privilege escalation, regardless of acceptEnv policy.
		if isDangerousEnvVar(variableName) {
			continue
		}

		// Always reject names that would corrupt the incubator's "su -w"
		// allowlist (see reservedEnvKey), regardless of acceptEnv policy.
		if forbiddenEnvKey(variableName) {
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
//
// Matching is iterative with a single backtracking point (the most recent
// '*'), so it runs in time linear in the target per '*' segment. A naive
// recursive matcher is exponential in the number of '*'s, and can be driven
// by attacker-supplied acceptEnv patterns and variable names.
func matchAcceptEnvPattern(pattern string, target string) bool {
	var (
		p, t  int  // current position in pattern and target
		starP = -1 // index of the most recent '*' in the pattern
		starT = -1 // position in the target where that '*' started matching
	)
	for t < len(target) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			// Register the most recent '*' before any literal match, so a
			// '*' in the pattern is always a backtrack point even when the
			// target has a literal '*' at the same position.
			starP = p
			starT = t
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == target[t]):
			// Match one character.
			p++
			t++
		case starP >= 0:
			// Mismatch: let the most recent '*' consume one more
			// character of the target and retry the rest of the
			// pattern from just after it.
			p = starP + 1
			starT++
			t = starT
		default:
			// Mismatch with no '*' left to fall back on.
			return false
		}
	}
	// The target is exhausted; the pattern must be too, modulo trailing '*'s,
	// which match the empty string.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
