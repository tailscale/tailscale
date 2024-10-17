// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"fmt"
	"slices"
	"strings"
)

// filterEnv filters a passed in environ string slice (a slice with strings
// representing environment variables in the form "key=value") based on
// the supplied slice of acceptEnv values.
//
// acceptEnv is a slice of environment variable names that are allowlisted
// for the SSH rule in the policy file.
//
// acceptEnv values may contain * and ? wildcard characters which match against
// zero or one or more characters and a single character respectively.
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
